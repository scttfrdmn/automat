// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/catalog"
	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
	"github.com/scttfrdmn/automat/internal/verify"
	"github.com/scttfrdmn/automat/internal/version"
)

// Exit codes for `verify`, distinct from preflight's (cmd/automat/preflight.go)
// even though the meaning parallels them: DESIGN §12 wants verify's own
// taxonomy, and reusing preflight's constants would make a change to one
// command's exit codes silently ripple into the other's.
const (
	// exitVerifyDrift: the policy layer found drift, an orphan, or a name
	// collision — something an operator should look at.
	exitVerifyDrift = 2
	// exitVerifyUnknown: nothing was found wrong, but a check could not be
	// completed (e.g. a read was denied), so "clean" would overstate the
	// evidence.
	exitVerifyUnknown = 3
)

// reVerifyAccountID matches the same class internal/evidence's own
// account-id pattern does: a bare 12-digit AWS account id.
var reVerifyAccountID = regexp.MustCompile(`^[0-9]{12}$`)

// newVerifyCmd builds `automat verify` — DESIGN §12, scoped to what a `vend`
// built by this binary actually produces.
//
// # Two layers, not four
//
// DESIGN §12 names four: policy, detective, procedural, freshness. Only the
// first and last are checked here. The detective layer (Config recorder,
// conformance pack) and the procedural layer (attestation stubs) both check
// something DESIGN §7 step 5 — internal/baseline — was meant to install, and
// that package does not exist (the same gap `vend`'s own plan and evidence
// manifest disclose, docs/cli-surface.md D3). This command says so in its own
// output rather than staying silent about it, the same discipline `vend`
// follows for the identical gap.
//
// # --account, not --account | --ou
//
// DESIGN §12 states the flag as `--account <id> | --ou <id>`. It cannot be
// built as written: baseline-protection — compiled into every vend, never
// optional — exempts automat's in-account automation role from its Deny
// statements, and that role's ARN embeds the account id
// (internal/compilesets's renderCondition). An OU with no account in hand has
// no ARN to render, so compilesets.Pack cannot produce the expected policy set
// for an OU-only check. --account resolves its own parent OU via ListParents
// and checks the policies attached there; a bare --ou flag is not offered
// rather than offered and silently wrong.
func newVerifyCmd(g *globals) *cobra.Command {
	var (
		accountID    string
		profilePath  string
		overridePath string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check a vended account against what it should be",
		Long: "Re-checks an account against the environment profile that vended it: the\n" +
			"policy layer (do the attached service control policies still match a fresh\n" +
			"compile) and the freshness layer (has the profile's review_by date passed).\n\n" +
			"The detective layer (Config recorder, conformance pack) and the procedural\n" +
			"layer (attestation stubs) are NOT checked: this build of automat has no\n" +
			"internal/baseline package, so nothing installs them for `vend` to check\n" +
			"either, and a check here would be reporting on something that cannot exist\n" +
			"yet. This command's output says so explicitly rather than staying silent.\n\n" +
			"Read-only: this command holds no write grant on anything it inspects.\n\n" +
			"Exit codes are for cron and CI: 0 clean, 2 drift or an orphan was found,\n" +
			"3 nothing was found wrong but a check could not be completed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			if accountID == "" {
				return fmt.Errorf("no account was given: pass --account <id>. verify checks one " +
					"account's attached policies against a fresh compile of the environment profile " +
					"that vended it")
			}
			if !reVerifyAccountID.MatchString(accountID) {
				return fmt.Errorf("--account %q is not a 12-digit AWS account id", accountID)
			}
			if profilePath == "" {
				return fmt.Errorf("no environment profile was given: pass --environment-profile " +
					"<file.json>. verify recompiles the same document `vend` compiled, to learn what " +
					"should be attached; it does not read one back out of the account")
			}

			in, err := loadVerifyInput(profilePath, accountID, overridePath)
			if err != nil {
				return err
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
			verifyAPI, err := g.orgVerifyClient(ctx, region, profile)
			if err != nil {
				return err
			}

			ident, err := stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
					"run `automat login`, or set AWS_PROFILE to a profile with valid credentials; "+
						"the evidence record verify writes names the identity that ran it")
			}
			callerARN := aws.ToString(ident.Arn)

			target, err := verifyParentOf(ctx, readAPI, accountID)
			if err != nil {
				return err
			}

			policyReport, err := verify.CheckPolicy(ctx, verifyAPI, target, in.packed)
			if err != nil {
				return err
			}
			now := time.Now()
			freshness := verify.CheckFreshness("environment profile "+in.profile.Meta.ID, in.profile.ReviewBy, now)

			honesty, err := verify.StructuralHonesty(in.sets)
			if err != nil {
				return err
			}

			// The read-and-diff half of ROADMAP.md's "Remote evidence mirror"
			// backlog item, item 2 — the half that actually closes (not just
			// narrows) docs/open-questions.md's Q21 residual. Checked BEFORE
			// this run's own OpVerify record is appended below: see
			// checkMirrorDrift's own doc comment for why the ordering matters
			// — comparing AFTER this run re-uploads would make local and
			// mirror agree by construction every time, hiding exactly the
			// tamper this check exists to catch.
			mirrorReports, mderr := checkMirrorDrift(ctx, g, region, profile, accountID,
				in.profile.Baseline.Evidence, now)
			if mderr != nil {
				return mderr
			}

			out := cmd.OutOrStdout()
			if err := renderVerifyReport(out, accountID, target, policyReport, freshness, honesty, mirrorReports); err != nil {
				return err
			}

			signer, serr := evidenceSigner(ctx, g, region, profile, orgCtx)
			if serr != nil {
				return serr
			}
			manifestPath, writtenManifest, werr := writeVerifyEvidence(in, accountID, target, callerARN, now,
				policyReport, mirrorReports, signer, out)
			if werr != nil {
				return werr
			}
			if manifestPath != "" {
				if _, perr := fmt.Fprintf(out, "\nEvidence: %s\n", manifestPath); perr != nil {
					return fmt.Errorf("write the result: %w", perr)
				}
			}

			// Additive and best-effort, after the local write above has already
			// succeeded unconditionally — the same priority writeVendEvidence's own
			// comment states for `vend` (DESIGN §11's "local copy always"). verify
			// has no warnings-rendering path of its own, so a failed upload prints a
			// plain stderr line rather than failing this command.
			if writtenManifest != nil {
				mirrors, merr := evidenceMirror(ctx, g, region, profile, in.profile.Baseline.Evidence)
				if merr != nil {
					if _, perr := fmt.Fprintf(cmd.ErrOrStderr(),
						"warning: could not build the evidence mirror: %v\n", merr); perr != nil {
						return fmt.Errorf("write the warning: %w", perr)
					}
				} else {
					for _, warn := range uploadToMirrors(ctx, mirrors, evidenceManifestKey(manifestPath), writtenManifest) {
						if _, perr := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warn); perr != nil {
							return fmt.Errorf("write the warning: %w", perr)
						}
					}
				}
			}

			switch {
			case !policyReport.Clean(), anyMirrorDrifted(mirrorReports):
				return &exitError{code: exitVerifyDrift}
			case freshness.Unparseable, anyMirrorUnreachable(mirrorReports):
				return &exitError{code: exitVerifyUnknown}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&accountID, "account", "", "the account to check (required)")
	f.StringVar(&profilePath, "environment-profile", "",
		"the environment profile this account was vended from (required)")
	f.StringVar(&overridePath, "override", "",
		"path to an override file resolving a Config-rule parameter conflict the union "+
			"could not settle on its own (DESIGN §9) — must match the one `vend` used, or the "+
			"recompiled expected policy set will not be the one actually attached")
	return cmd
}

// verifyInput is the already-resolved side of a verify run: the environment
// profile plus the compiled, narrowed, packed policy set it produces for
// accountID.
type verifyInput struct {
	profile     *envprofile.Profile
	contentHash string
	sets        *catalog.Resolved
	packed      *compilesets.Packed
}

// loadVerifyInput resolves the environment profile to the same compiled,
// narrowed, packed policy set `vend` would produce for accountID — the
// expected side of the comparison.
//
// Deliberately not sharing vend.go's loadVendInput/vendInput: that type also
// resolves a destination OU, a name, an email, and a resume token, none of
// which verify has any use for, and threading an unused vendInput through
// verify's call path would let a vend-only field silently start mattering to
// a command it has no business touching.
func loadVerifyInput(profilePath, accountID, overridePath string) (*verifyInput, error) {
	p, err := envprofile.Load(profilePath, envprofile.LoadOptions{})
	if err != nil {
		return nil, err
	}
	hash, err := p.ContentHash()
	if err != nil {
		return nil, fmt.Errorf("hashing environment profile %s: %w", profilePath, err)
	}

	sets, err := catalog.ResolveControlSets(p.ControlSets, catalog.Options{})
	if err != nil {
		return nil, err
	}

	var overrides *compilesets.Overrides
	if overridePath != "" {
		overrides, err = compilesets.LoadOverrides(overridePath)
		if err != nil {
			return nil, err
		}
	}
	merged, err := compilesets.MergeWithOverrides(overrides, sets.Artifacts...)
	if err != nil {
		return nil, err
	}
	var permittedRegions, permittedServices []string
	if p.Permitted != nil {
		permittedRegions, permittedServices = p.Permitted.Regions, p.Permitted.Services
	}
	narrowed, err := compilesets.Narrow(merged, compilesets.NarrowOptions{
		Regions:   permittedRegions,
		Services:  permittedServices,
		ProfileID: p.Meta.ID,
	})
	if err != nil {
		return nil, err
	}

	packed, err := compilesets.Pack(narrowed.Merged, compilesets.PackOptions{
		NamePrefix:        "automat-" + p.Meta.ID,
		AutomationRoleARN: automationRoleARNFor(accountID, p),
	})
	if err != nil {
		return nil, err
	}
	return &verifyInput{profile: p, contentHash: hash, sets: sets, packed: packed}, nil
}

// automationRoleARNFor renders the in-account automation role's ARN the same
// way vend.go's vendInput.automationRoleARN does, from a known account id
// rather than one a plan does not have yet — verify is only ever called
// against an account that already exists, so the "unknown until created"
// case that method's own doc comment describes does not apply here.
//
// The partition is assumed to be "aws": verify has no signed-in caller ARN to
// read a partition from the way vend does (vend.go's partitionOf(caller.ARN)).
// If a GovCloud or China deployment needs this, the fix is threading the
// partition through from an authenticated call, not guessing further here.
func automationRoleARNFor(accountID string, p *envprofile.Profile) string {
	return "arn:aws:iam::" + accountID + ":role/" + p.Baseline.AutomationRole.RoleName()
}

// verifyParentOf resolves the OU or root an account currently sits under, via
// the read-only awsapi.OrgAPI — never brokered, matching preflight's own use
// of this interface: ListParents on an account is a read every state can make
// with its own credentials (DESIGN §5's brokering exists for CreateAccount and
// CreateOrganizationalUnit, not for reads).
func verifyParentOf(ctx context.Context, api awsapi.OrgAPI, accountID string) (string, error) {
	out, err := api.ListParents(ctx, &organizations.ListParentsInput{ChildId: aws.String(accountID)})
	switch {
	case err == nil:
	case awsapi.APIErrorCode(err) == "ChildNotFoundException":
		return "", fmt.Errorf("cannot verify account %s: no account with that id exists in this "+
			"organization", accountID)
	default:
		return "", awsapi.Denied(err, "organizations:ListParents", accountID, "",
			"grant organizations:ListParents on "+accountID+" to the identity running verify")
	}
	if len(out.Parents) == 0 {
		return "", fmt.Errorf("cannot verify account %s: AWS reported no parent for it, which should "+
			"be impossible for an account in an organization", accountID)
	}
	return aws.ToString(out.Parents[0].Id), nil
}

// renderVerifyReport prints the policy and freshness findings, the
// per-control enforcement-class breakdown DESIGN §12 calls "structural
// honesty" — how many of the compiled controls this tool enforces itself, how
// many require a documented process outside this tool, and how many require
// continuous evidence collection outside this tool's scope. Computed from the
// artifact (verify.StructuralHonesty), not asserted in prose, so the report
// states its own limits without pitching anything — and, when at least one
// mirror is configured, the mirror-drift findings from ROADMAP.md's "Remote
// evidence mirror" slice 2 (docs/open-questions.md Q21).
//
// mirrorReports may be nil (no mirror bucket configured at all — the
// common, today's-default case), in which case the section is omitted
// entirely rather than printed empty: "nothing to check" and "checked, found
// nothing" are different claims, and the absence of the section IS the
// former's honest rendering, distinct from a checked-clean line for the
// latter (see checkMirrorDrift's own doc comment).
func renderVerifyReport(w io.Writer, accountID, target string,
	policy *verify.PolicyReport, freshness verify.FreshnessStatus, honesty *verify.StructuralHonestyReport,
	mirrorReports []evidence.MirrorDriftReport) error {
	p := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}

	// target is quoted, accountID is not: accountID passed reVerifyAccountID
	// before any of this ran, so its character class is already known, while
	// target is whatever ListParents returned and has been checked against
	// nothing. Same for an orphan's name below. AUDIT-0 M1's discipline: a
	// value that can carry a newline can forge a line of a report, and this
	// report is what an operator reads to decide whether an account drifted.
	if err := p("Account %s (OU/root %q)\n\n", accountID, target); err != nil {
		return err
	}

	if err := p("Policy layer:\n"); err != nil {
		return err
	}
	for _, s := range policy.Expected {
		line := s.Name
		switch {
		case !s.Attached:
			line += ": NOT ATTACHED"
		case !s.Owned:
			line += ": attached but not carrying automat's owner tag (a name collision, not automat's drift)"
		case !s.Matches:
			line += ": ATTACHED, content differs from a fresh compile"
		default:
			line += ": matches"
		}
		if err := p("  %s\n", line); err != nil {
			return err
		}
	}
	for _, o := range policy.Orphans {
		if err := p("  orphan (attached, automat's, no longer named by this compile): %q\n", o); err != nil {
			return err
		}
	}
	if len(policy.Expected) == 0 && len(policy.Orphans) == 0 {
		if err := p("  no preventive controls in this compile; nothing to attach\n"); err != nil {
			return err
		}
	}

	if err := p("\nFreshness layer:\n  %s\n", freshness.String()); err != nil {
		return err
	}

	if err := p("\nStructural honesty:\n"); err != nil {
		return err
	}
	for _, line := range strings.Split(honesty.String(), "\n") {
		if err := p("  %s\n", line); err != nil {
			return err
		}
	}
	if err := p("  (detective and procedural findings are not checked in this build — see " +
		"`automat verify --help`)\n"); err != nil {
		return err
	}

	if len(mirrorReports) > 0 {
		if err := p("\nEvidence mirror layer:\n"); err != nil {
			return err
		}
		for _, mr := range mirrorReports {
			line, lerr := renderMirrorDriftLine(mr)
			if lerr != nil {
				return lerr
			}
			if err := p("  %s\n", line); err != nil {
				return err
			}
		}
	}

	return p("\nautomat %s\n", version.Version)
}

// renderMirrorDriftLine renders one evidence.MirrorDriftReport as a single
// report line — its own line, own outcome consideration, distinct from the
// "Policy layer:"/"Structural honesty:" sections above, per this task's own
// scope statement. bucket is quoted for the same reason renderVerifyReport
// quotes target and an orphan's name: it names a bucket read out of the
// environment profile, an operator-supplied document, not one of this
// binary's own literals.
func renderMirrorDriftLine(mr evidence.MirrorDriftReport) (string, error) {
	switch {
	case !mr.Checked:
		return fmt.Sprintf("%q: could not verify — %s", mr.Bucket, mr.Detail), nil
	case !mr.Drifted:
		return fmt.Sprintf("%q: matches the local manifest", mr.Bucket), nil
	case mr.DriftKind == evidence.DriftKindTruncation:
		return fmt.Sprintf("%q: TRUNCATED relative to the local manifest — %s", mr.Bucket, mr.Detail), nil
	default:
		return fmt.Sprintf("%q: DISAGREES with the local manifest — %s", mr.Bucket, mr.Detail), nil
	}
}

// anyMirrorDrifted reports whether any mirror-drift report found a genuine
// disagreement or truncation — the condition that pushes verify's exit code
// toward exitVerifyDrift, the same way !policy.Clean() does.
func anyMirrorDrifted(reports []evidence.MirrorDriftReport) bool {
	for _, r := range reports {
		if r.Drifted {
			return true
		}
	}
	return false
}

// anyMirrorUnreachable reports whether any configured mirror could not be
// read — the third, distinct state (checkMirrorDrift's own doc comment),
// which must move the exit code toward exitVerifyUnknown rather than either
// exitVerifyDrift (that would call an unreadable mirror a drift finding) or
// a clean exit (that would call it a pass).
func anyMirrorUnreachable(reports []evidence.MirrorDriftReport) bool {
	for _, r := range reports {
		if !r.Checked {
			return true
		}
	}
	return false
}

// checkMirrorDrift runs ROADMAP.md's "Remote evidence mirror" slice 2 — the
// read-and-diff half that closes (for an account with a mirror configured)
// docs/open-questions.md's Q21 residual — against every mirror bucket named
// program.Baseline.Evidence, reusing evidenceMirrorReaders' bucket resolution
// (the same one evidenceMirror's write side already uses) rather than
// re-reading InAccountBucket/ManagementMirrorBucket a second time.
//
// # Why this must run BEFORE writeVerifyEvidence appends this run's own record
//
// Every evidence-writing command in this codebase uploads to its mirror
// AFTER the local write (evidenceMirror's own doc comment: "the mirror
// upload is additive and best-effort, after the local write above has
// already succeeded"). If checkMirrorDrift ran after that upload, this run's
// own OpVerify record would already be on both copies, and a rewrite
// targeting an EARLIER record would be masked: local and mirror would agree
// on their current tails regardless of what happened to the history beneath
// them, because both received the identical fresh write moments before the
// comparison. Running the check against the mirror's state as of the START
// of this run — before this run touches either copy — is what makes the
// comparison meaningful.
//
// Returns nil, nil (not an empty non-nil slice) when no mirror is
// configured: renderVerifyReport and writeVerifyEvidence both treat a nil
// slice as "nothing to check" and omit the section/skip the finding
// entirely, which is the correct rendering of "opt-in, and not opted into"
// (docs/open-questions.md Q21's own "closes the residual for accounts with a
// mirror configured" scoping).
func checkMirrorDrift(ctx context.Context, g *globals, region, profile, accountID string,
	targets *envprofile.OutputTargets, now time.Time) ([]evidence.MirrorDriftReport, error) {
	readers, err := evidenceMirrorReaders(ctx, g, region, profile, targets)
	if err != nil {
		return nil, err
	}
	if len(readers) == 0 {
		return nil, nil
	}

	dir, err := evidence.OpenDir(".", targets.Dir(envprofile.DefaultEvidenceDir))
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()

	key, local, err := openActiveManifest(dir, accountID, "", now.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("cannot open the evidence manifest for account %s: %w", accountID, err)
	}

	reports := make([]evidence.MirrorDriftReport, len(readers))
	for i, r := range readers {
		report := evidence.MirrorDrift(ctx, r.reader, r.bucket, key, local)
		reports[i] = *report
	}
	return reports, nil
}

// writeVerifyEvidence appends an OpVerify record to the account's evidence
// manifest, following the same OpenDir/LoadOrNew/Append/Write sequence
// writeVendEvidence (vend.go) uses.
//
// # The outcome is the finding, not the exit status of the process (AUDIT-4 H2)
//
// It used to be evidence.OutcomeSuccess unconditionally, so a run that reported
// drift and exited 2 left a record reading `"outcome": "success"` — and the
// manifest is the durable artifact, read long after the exit code is gone. A
// reader counting successful verify records would have counted the drift ones.
//
// A drifted account is recorded as `failure` with the required error block. Not
// `parked`: parked means real AWS state was left behind for `vend --resume` to
// find (evidence.OutcomeParked's own doc comment), and verify wrote nothing to
// resume. The `failure` here is the CHECK's finding, which is what an operation
// named "verify" failing can only mean — it did not fail to run, it ran and
// found the account is not what the profile says.
//
// Freshness is deliberately not part of this: a lapsed review_by is a warning
// that changes no exit code (DESIGN §11a, §12), and a record marked failure for
// a date would say the account drifted when nothing about it moved.
//
// Mirror drift (mirrorReports, ROADMAP.md's "Remote evidence mirror" slice 2)
// follows the SAME rule the policy layer does, not freshness's: a mirror
// that disagrees with the local manifest IS a finding this check made, so it
// pushes outcome to failure exactly the way a missing or differing policy
// does (mirrorDriftError, mirroring verifyDriftError's own shape per
// CLAUDE.md rule 7). An UNREACHABLE mirror (Checked false) does NOT flip the
// outcome — that is "could not verify", the same non-claim freshness's own
// Unparseable makes, and a record marked failure for a network error or a
// permission denial would say the account drifted when nothing about it was
// shown to have moved.
//
// # Rotation (Q23, docs/open-questions.md)
//
// `verify` is the command this project's own research backlog names as the one
// that actually reaches evidence.RotateThresholdRecords in practice — run
// hourly against the same account, it appends an OpVerify record every time,
// success or drift, with no pruning (docs/open-questions.md's Q23 entry). So the
// active manifest is resolved by following any rotation pointer already in
// place (openActiveManifest), and after this run's record is appended, the
// threshold is checked and a rotation performed if crossed
// (writeManifestWithRotation) — visibly, via a notice on out, never silently.
func writeVerifyEvidence(in *verifyInput, accountID, target, callerARN string, now time.Time,
	policy *verify.PolicyReport, mirrorReports []evidence.MirrorDriftReport,
	signer evidence.Signer, out io.Writer) (string, *evidence.Manifest, error) {
	localDir := in.profile.Baseline.Evidence.Dir(envprofile.DefaultEvidenceDir)

	dir, err := evidence.OpenDir(".", localDir)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = dir.Close() }()

	nowStr := now.UTC().Format(time.RFC3339)
	key, m, err := openActiveManifest(dir, accountID, "", nowStr)
	if err != nil {
		return "", nil, fmt.Errorf("cannot open the evidence manifest for account %s: %w\n"+
			"automat refuses to continue a chain it cannot read, because a manifest rewritten from "+
			"scratch over a damaged one is the one failure the hash chain exists to make visible",
			accountID, err)
	}

	outcome, recErr := evidence.OutcomeSuccess, (*evidence.RecordError)(nil)
	switch {
	case !policy.Clean() && anyMirrorDrifted(mirrorReports):
		outcome = evidence.OutcomeFailure
		recErr = verifyDriftError(policy)
		recErr.Message += " Additionally, " + mirrorDriftError(mirrorReports).Message
	case !policy.Clean():
		outcome, recErr = evidence.OutcomeFailure, verifyDriftError(policy)
	case anyMirrorDrifted(mirrorReports):
		outcome, recErr = evidence.OutcomeFailure, mirrorDriftError(mirrorReports)
	}
	rec := evidence.Record{
		Timestamp: nowStr,
		Operation: evidence.OpVerify,
		Outcome:   outcome,
		Operator:  evidence.Operator{ARN: callerARN},
		Err:       recErr,
		Target:    &evidence.Target{AccountID: accountID, OUID: target},
		EnvProfile: &evidence.EnvProfileRef{
			ID: in.profile.Meta.ID, ContentSHA256: in.contentHash,
			SchemaVersion: in.profile.SchemaVersion, ReviewBy: in.profile.ReviewBy,
			VerifiedSignatures: []evidence.VerifiedSignature{},
		},
		ToolVersion: version.Version,
	}
	if _, err := m.Append(rec, signer); err != nil {
		return "", nil, fmt.Errorf("cannot append the verify record for account %s: %w", accountID, err)
	}
	return writeManifestWithRotation(dir, key, m, signer, nowStr, out)
}

// verifyDriftError is the RecordError a drifted verify record carries.
//
// The message names each finding rather than saying "drift was found", because
// the manifest is what an operator reads weeks later with no terminal scrollback
// (evidence.RecordError's own doc comment, CLAUDE.md rule 7) — and the three
// findings need three different actions: a missing policy is re-attached by
// re-running `vend`, a differing one by correcting whichever side is wrong, and
// an orphan by a detach automat cannot perform at all.
//
// Every policy name is quoted for the same reason renderVerifyReport quotes
// them: a name reaches this text from AWS, and this text goes into a document.
func verifyDriftError(policy *verify.PolicyReport) *evidence.RecordError {
	var missing, differs, unowned []string
	for _, s := range policy.Expected {
		switch {
		case !s.Attached:
			missing = append(missing, fmt.Sprintf("%q", s.Name))
		case !s.Owned:
			unowned = append(unowned, fmt.Sprintf("%q", s.Name))
		case !s.Matches:
			differs = append(differs, fmt.Sprintf("%q", s.Name))
		}
	}
	orphans := make([]string, 0, len(policy.Orphans))
	for _, o := range policy.Orphans {
		orphans = append(orphans, fmt.Sprintf("%q", o))
	}

	parts := make([]string, 0, 4)
	add := func(names []string, what string) {
		if len(names) > 0 {
			parts = append(parts, what+": "+strings.Join(names, ", "))
		}
	}
	add(missing, "not attached")
	add(differs, "attached but the content differs from a fresh compile")
	add(unowned, "attached under automat's name without automat's owner tag, so this is a "+
		"name collision rather than automat's drift")
	add(orphans, "attached, automat's, and no longer named by this compile")

	return &evidence.RecordError{
		Message: "the policy layer does not match a fresh compile of this environment profile. " +
			strings.Join(parts, "; "),
		Action:      "organizations:ListPoliciesForTarget",
		Resource:    policy.Target,
		Remediation: verifyDriftRemediation(len(missing)+len(differs) > 0, len(orphans) > 0),
	}
}

// verifyDriftRemediation names the action for the findings actually present.
// Split out so the sentence about a detach automat cannot perform appears only
// when there is an orphan to detach, rather than in every drift record.
func verifyDriftRemediation(reattach, orphaned bool) string {
	var parts []string
	if reattach {
		parts = append(parts, "re-run `automat vend` with this environment profile (and the same "+
			"--override, if one was used) to re-ensure the policies; it is idempotent, and a policy "+
			"whose content differs is corrected in place rather than replaced")
	}
	if orphaned {
		parts = append(parts, "an orphan is left in force and cannot be removed by this build — "+
			"automat holds no DetachPolicy — so detach it in the management account if it should "+
			"not apply. It is a Deny policy, so leaving it makes the account more restricted than "+
			"this profile asks for, not less")
	}
	return strings.Join(parts, ". ")
}

// mirrorDriftError is the RecordError a mirror-drifted verify record
// carries — verifyDriftError's own shape (CLAUDE.md rule 7: which action,
// which resource, what grant/step would fix it), applied to
// ROADMAP.md's "Remote evidence mirror" slice 2 finding instead of the
// policy layer's. Called only when anyMirrorDrifted(reports) is true, so at
// least one entry has Drifted set; unreachable mirrors (Checked false) are
// a distinct, non-failing state and are not named here (writeVerifyEvidence's
// own doc comment).
func mirrorDriftError(reports []evidence.MirrorDriftReport) *evidence.RecordError {
	var parts []string
	for _, r := range reports {
		if !r.Drifted {
			continue
		}
		parts = append(parts, fmt.Sprintf("%q %s: %s", r.Bucket, r.DriftKind, r.Detail))
	}
	return &evidence.RecordError{
		Message: "the evidence mirror does not match the local manifest. " + strings.Join(parts, "; "),
		Action:  "s3:GetObject",
		Remediation: "the local manifest and its mirrored copy in the bucket(s) named above disagree; " +
			"this is docs/open-questions.md Q21's own residual made concrete — determine which copy is " +
			"the tampered one (a rewrite that truncates records and recomputes the genesis anchor is " +
			"internally consistent by itself, which is exactly why a second copy is what catches it), " +
			"and treat the account as needing a full manual review rather than a re-run of `vend`, " +
			"which would not repair a chain that has already been edited",
	}
}
