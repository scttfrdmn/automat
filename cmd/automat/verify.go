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
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/baseline"
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
// # Four layers, now that internal/baseline exists
//
// DESIGN §12 names four: policy, detective, procedural, freshness. All four
// are checked as of ROADMAP.md's "internal/baseline, slices 2-9" item 9 —
// wiring detective and procedural against what internal/baseline's own
// Ensure* methods install. The detective layer (verify.CheckDetective, this
// file's configVerifyClient) reads the Config recorder, delivery channel,
// and conformance pack through the same read-only, in-child-assumed session
// vend's own baseline steps establish through with a write-carrying one. The
// procedural layer (verify.CheckProcedural) reads the attestation stub
// directory EnsureAttestationStubs writes into, locally, no AWS call at all.
//
// Both layers are "opt-in, and not opted into" the same way the mirror layer
// already is (checkMirrorDrift's own doc comment): a profile whose
// config_recorder.enabled is false, or whose compile binds no Config rule,
// or which names no procedural control at all, produces no finding for the
// corresponding section — not a failure, because nothing was asked for.
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
		Long: "Re-checks an account against the environment profile that vended it, across\n" +
			"all four of DESIGN §12's layers:\n\n" +
			"  - policy: do the attached service control policies still match a fresh compile\n" +
			"  - detective: does the AWS Config recorder exist and record, does the delivery\n" +
			"    channel point at the right bucket, and does the conformance pack's deployed\n" +
			"    parameters match a fresh compile — each checked only when the profile asked\n" +
			"    for it; a profile that never enabled the recorder, or whose compile binds no\n" +
			"    Config rule, is reported as \"not configured\", not as a failure\n" +
			"  - procedural: does each deduped attestation stub exist, does it carry content,\n" +
			"    and is it stale against its own declared frequency\n" +
			"  - freshness: has the profile's review_by date passed\n\n" +
			"Detective and procedural findings that could not be checked at all — the\n" +
			"in-child session could not be assumed, or a read was denied — are reported as\n" +
			"unknown, never as drift: a denial is not evidence that something is wrong.\n\n" +
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

			// The detective and procedural layers — ROADMAP.md's "internal/
			// baseline, slices 2-9" item 9, wiring verify against what
			// internal/baseline's own Ensure* methods install. detectiveUnknown
			// and proceduralUnknown each report "could not be checked" (an
			// in-child session could not be assumed, a read was denied, or the
			// local stub directory could not be read) as a state DISTINCT from
			// a report that came back clean — see runDetectiveCheck's own doc
			// comment for why that distinction pushes the exit code toward
			// exitVerifyUnknown, never exitVerifyDrift.
			detectiveReport, detectiveUnknown := runDetectiveCheck(ctx, g, region, profile,
				partitionOf(callerARN), accountID, in)
			proceduralReport, proceduralUnknown := runProceduralCheck(
				in.profile.Baseline.Attestations.Dir(envprofile.DefaultAttestationDir),
				in.attestationGroups, now)

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
			if err := renderVerifyReport(out, accountID, target, policyReport, freshness, honesty,
				detectiveReport, detectiveUnknown, proceduralReport, mirrorReports); err != nil {
				return err
			}

			signer, serr := evidenceSigner(ctx, g, region, profile, orgCtx)
			if serr != nil {
				return serr
			}
			manifestPath, writtenManifest, werr := writeVerifyEvidence(in, accountID, target, callerARN, now,
				policyReport, detectiveReport, proceduralReport, mirrorReports, signer, out)
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
			case !policyReport.Clean(), !detectiveReport.Clean(), !proceduralReport.Clean(), anyMirrorDrifted(mirrorReports):
				return &exitError{code: exitVerifyDrift}
			case freshness.Unparseable, detectiveUnknown, proceduralUnknown, anyMirrorUnreachable(mirrorReports):
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
// accountID, plus the two detective/procedural expectations
// internal/verify's own doc comment requires a caller to resolve before
// calling CheckDetective/CheckProcedural (that package "receives
// already-resolved values... and reports on them, so it has no opinion
// about where they came from").
type verifyInput struct {
	profile     *envprofile.Profile
	contentHash string
	sets        *catalog.Resolved
	packed      *compilesets.Packed

	// packName and packInputParams are the conformance pack's expected
	// identity and resolved parameters, computed the SAME way
	// vendConformancePackStep (vend.go) computes them for its own
	// EnsureConformancePack call — conformancePackName and
	// baseline.RenderConformancePackTemplate over
	// narrowed.Merged.SortedConfigRules(). The rendered template body itself
	// is not kept: CheckDetective compares only ConformancePackInputParameters
	// (baseline.SameInputParameters' own doc comment explains why that is the
	// only drift check possible at all — DescribeConformancePacks never
	// returns deployed template text), so the body has no use here. packName
	// is empty exactly when vendConformancePackStep's own no-op condition
	// holds (the compile binds no Config rule at all), which CheckDetective
	// reads as "no pack was asked for", not as an absent one.
	packName        string
	packInputParams []configtypes.ConformancePackInputParameter

	// attestationGroups are compilesets.DedupeAttestations' own return value
	// over sets.Artifacts — the same call vendAttestationStubsStep makes, so
	// CheckProcedural checks against the identical stub filenames and
	// frequencies a vend would have written.
	attestationGroups []compilesets.DedupedAttestation
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

	in := &verifyInput{profile: p, contentHash: hash, sets: sets, packed: packed}

	// The conformance pack's expected identity and content — computed the
	// SAME way vendConformancePackStep computes them for its own
	// EnsureConformancePack call, so CheckDetective compares against the
	// pack a vend of this profile would actually deploy. Left at their zero
	// values (packName empty) when the compile binds no Config rule at all,
	// matching vendConformancePackStep's own no-op condition — a caller
	// asking CheckDetective about a pack that no vend would ever create is
	// not this function's job to invent one for.
	rules := narrowed.Merged.SortedConfigRules()
	if len(rules) > 0 {
		in.packName = conformancePackNameFor(p.Meta.ID)
		// The template body is discarded (see verifyInput.packInputParams'
		// own doc comment for why): only the resolved parameters are kept,
		// since that is the one thing CheckDetective can compare against
		// what DescribeConformancePacks returns.
		_, in.packInputParams, err = baseline.RenderConformancePackTemplate(rules)
		if err != nil {
			return nil, err
		}
	}

	// The deduped attestation groups — compilesets.DedupeAttestations over
	// the SAME resolved artifacts vendAttestationStubsStep dedupes, so
	// CheckProcedural checks against the identical stub filenames and
	// frequencies a vend would have written. nil (not an error) when the
	// compile carries no procedural control at all, DedupeAttestations' own
	// documented return for that case.
	in.attestationGroups, err = compilesets.DedupeAttestations(sets.Artifacts...)
	if err != nil {
		return nil, err
	}

	return in, nil
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

// runDetectiveCheck resolves verify's detective layer, assuming the SAME
// OrganizationAccountAccessRole session (via g.configVerifyClient) `vend`'s
// own baseline steps assume into with a write-carrying client — but through
// the read-only awsapi.ConfigVerifyAPI, so nothing this call does can ever
// mutate the account's Config setup (ConfigVerifyAPI's own doc comment).
//
// # "Cannot be checked" is swallowed here, not propagated as a command failure
//
// Both a failed assumption (the delegation policy does not grant sts:AssumeRole
// into the automation role, or the role was never created) and a denied
// Describe call inside verify.CheckDetective are read as "this layer could not
// be checked", returned as (nil, true) rather than as an error that would fail
// the whole command. This is the exact distinction freshness's own Unparseable
// and the evidence-mirror layer's own "unreachable" state already draw
// (checkMirrorDrift's doc comment): a denial is not evidence that the account
// drifted, so it must not be reported alongside a genuine drift finding, and
// it must not silently read as clean either — RunE's exit-code switch moves
// detectiveUnknown to exitVerifyUnknown, never exitVerifyDrift or a plain 0.
//
// A no-op — no client built, no AWS call at all — when the profile asks for
// neither a Config recorder nor a conformance pack: attempting to assume into
// an account for a check that has nothing to check would be an AssumeRole call
// with no purpose, the same "opt-in, and not opted into" discipline
// DetectiveReport's own doc comment states for the fields themselves.
func runDetectiveCheck(ctx context.Context, g *globals, region, profile, partition, accountID string,
	in *verifyInput) (report *verify.DetectiveReport, unknown bool) {
	if !in.profile.Baseline.ConfigRecorder.Enabled && in.packName == "" {
		return &verify.DetectiveReport{}, false
	}

	api, err := g.configVerifyClient(ctx, region, profile, partition, accountID, envprofile.DefaultOrgAccessRole)
	if err != nil {
		return nil, true
	}

	automationRoleARN := automationRoleARNFor(accountID, in.profile)
	report, err = verify.CheckDetective(ctx, api, in.profile.Baseline.ConfigRecorder,
		automationRoleARN, in.packName, in.packInputParams)
	if err != nil {
		return nil, true
	}
	return report, false
}

// runProceduralCheck resolves verify's procedural layer, reading the local
// attestation-stub directory through verify.CheckProcedural.
//
// Mirrors runDetectiveCheck's own "cannot be checked, not a command failure"
// treatment for the identical reason: a local filesystem error reading the
// stub directory (a permission problem, a symlink refusal) is not evidence
// that a control's attestation is missing or stale, so it must land in
// exitVerifyUnknown rather than exitVerifyDrift or a hard failure that would
// abort the run before the report prints at all.
func runProceduralCheck(dir string, groups []compilesets.DedupedAttestation,
	now time.Time) (report *verify.ProceduralReport, unknown bool) {
	report, err := verify.CheckProcedural(dir, groups, now)
	if err != nil {
		return nil, true
	}
	return report, false
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
//
// detective and procedural are printed as their own sections, in DESIGN §12's
// own layer order (policy, detective, procedural, freshness) — each following
// the identical quoting discipline the policy section already applies to an
// AWS-supplied name (AUDIT-0 M1): a bucket name or a control id reaches this
// text from a document or from AWS, not from this binary's own literals, so
// it is quoted with %q the same way target and an orphan's name are.
// detectiveUnknown/proceduralUnknown each print "could not be checked" rather
// than either finding's own zero value, so a denied read never renders
// indistinguishably from "checked, found nothing wrong" (this file's own
// checkMirrorDrift precedent, restated for these two layers).
func renderVerifyReport(w io.Writer, accountID, target string,
	policy *verify.PolicyReport, freshness verify.FreshnessStatus, honesty *verify.StructuralHonestyReport,
	detective *verify.DetectiveReport, detectiveUnknown bool, procedural *verify.ProceduralReport,
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

	if err := p("\nDetective layer:\n"); err != nil {
		return err
	}
	if err := renderDetectiveSection(p, detective, detectiveUnknown); err != nil {
		return err
	}

	if err := p("\nProcedural layer:\n"); err != nil {
		return err
	}
	if err := renderProceduralSection(p, procedural); err != nil {
		return err
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

// renderDetectiveSection prints CheckDetective's findings, one line per
// configured piece — a nil Recorder/DeliveryChannel/ConformancePack means
// the profile never asked for it (DetectiveReport's own "opt-in, and not
// opted into" doc comment), printed as its own distinct line rather than
// omitted, so an operator reading the report sees "not configured" rather
// than wondering whether the check ran at all.
func renderDetectiveSection(p func(string, ...any) error, d *verify.DetectiveReport, unknown bool) error {
	if unknown {
		return p("  could not be checked: the in-child session could not be assumed, or a read " +
			"was denied\n")
	}
	if d == nil {
		return p("  not configured: this profile enables no Config recorder and binds no Config rule\n")
	}

	if d.Recorder == nil {
		if err := p("  Config recorder: not configured (baseline.config_recorder.enabled is false)\n"); err != nil {
			return err
		}
	} else {
		switch {
		case !d.Recorder.Present:
			if err := p("  Config recorder: NOT PRESENT\n"); err != nil {
				return err
			}
		case !d.Recorder.Recording:
			if err := p("  Config recorder: present but NOT RECORDING (created without being started)\n"); err != nil {
				return err
			}
		case !d.Recorder.ConfigMatches:
			if err := p("  Config recorder: recording, but its recording scope or role differs from a fresh compile\n"); err != nil {
				return err
			}
		default:
			if err := p("  Config recorder: present, recording, matches\n"); err != nil {
				return err
			}
		}
	}

	if d.DeliveryChannel == nil {
		if err := p("  Config delivery channel: not configured (baseline.config_recorder.enabled is false)\n"); err != nil {
			return err
		}
	} else {
		switch {
		case !d.DeliveryChannel.Present:
			if err := p("  Config delivery channel: NOT PRESENT (expected bucket %q)\n", d.DeliveryChannel.Bucket); err != nil {
				return err
			}
		case !d.DeliveryChannel.Matches:
			if err := p("  Config delivery channel: present, but delivers to a different bucket than "+
				"the expected %q\n", d.DeliveryChannel.Bucket); err != nil {
				return err
			}
		default:
			if err := p("  Config delivery channel: present, delivers to %q, matches\n", d.DeliveryChannel.Bucket); err != nil {
				return err
			}
		}
	}

	if d.ConformancePack == nil {
		return p("  Conformance pack: not configured (this compile binds no Config rule)\n")
	}
	switch {
	case !d.ConformancePack.Present:
		return p("  Conformance pack %q: NOT PRESENT\n", d.ConformancePack.Name)
	case !d.ConformancePack.Matches:
		return p("  Conformance pack %q: present, deployed parameters differ from a fresh compile\n",
			d.ConformancePack.Name)
	default:
		return p("  Conformance pack %q: present, matches\n", d.ConformancePack.Name)
	}
}

// renderProceduralSection prints CheckProcedural's findings, one line per
// deduped attestation group. An empty Stubs slice (no procedural control in
// this compile at all) is a distinct, explicitly stated line rather than a
// silently empty section.
func renderProceduralSection(p func(string, ...any) error, r *verify.ProceduralReport) error {
	if r == nil || len(r.Stubs) == 0 {
		return p("  no procedural control in this compile; nothing to attest\n")
	}
	for _, s := range r.Stubs {
		line := fmt.Sprintf("%q (%s, %s)", s.FileName, strings.Join(s.ControlIDs, ", "), s.Frequency)
		switch {
		case !s.Present:
			line += ": NOT WRITTEN"
		case s.Empty:
			line += ": present but EMPTY (never filled in)"
		case s.StaleChecked && s.Stale:
			line += ": STALE against its declared frequency"
		default:
			line += ": present, current"
		}
		if err := p("  %s\n", line); err != nil {
			return err
		}
	}
	return nil
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
	policy *verify.PolicyReport, detective *verify.DetectiveReport, procedural *verify.ProceduralReport,
	mirrorReports []evidence.MirrorDriftReport, signer evidence.Signer, out io.Writer) (string, *evidence.Manifest, error) {
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

	// Every genuine finding — policy, detective, procedural, mirror — pushes
	// outcome to failure, following the SAME rule (CLAUDE.md rule 7 applied
	// consistently): each is a definite answer this run computed, not a
	// "could not check" state. detective/procedural's own Clean() already
	// treats "not configured at all" as clean (DetectiveReport/
	// ProceduralReport's own doc comments), so a profile that never enabled
	// the recorder or named no procedural control never contributes a
	// finding here — this switch cannot be tricked into calling "nothing was
	// asked for" a failure.
	//
	// detectiveUnknown/proceduralUnknown are handled entirely by the CALLER
	// (RunE's own exit-code switch): an unchecked layer produces a nil
	// report from runDetectiveCheck/runProceduralCheck, and nil.Clean()
	// returns true (both types' own Clean() methods), so this function
	// never sees "could not check" as a drift finding — the same
	// non-claim freshness's own Unparseable and mirror's own Checked:false
	// already make, restated here rather than re-derived, because a record
	// marked failure for a denial or a network error would say the account
	// drifted when nothing about it was shown to have moved.
	var findings []*evidence.RecordError
	if !policy.Clean() {
		findings = append(findings, verifyDriftError(policy))
	}
	if !detective.Clean() {
		findings = append(findings, detectiveDriftError(detective))
	}
	if !procedural.Clean() {
		findings = append(findings, proceduralDriftError(procedural))
	}
	if anyMirrorDrifted(mirrorReports) {
		findings = append(findings, mirrorDriftError(mirrorReports))
	}

	outcome, recErr := evidence.OutcomeSuccess, (*evidence.RecordError)(nil)
	if len(findings) > 0 {
		outcome = evidence.OutcomeFailure
		recErr = findings[0]
		for _, f := range findings[1:] {
			recErr.Message += " Additionally, " + f.Message
		}
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

// detectiveDriftError is the RecordError a detective-layer drift record
// carries — verifyDriftError's own shape (CLAUDE.md rule 7), applied to
// CheckDetective's findings. Called only when !detective.Clean(), so at
// least one of Recorder/DeliveryChannel/ConformancePack is both non-nil
// (configured) and not itself Clean.
func detectiveDriftError(d *verify.DetectiveReport) *evidence.RecordError {
	var parts []string
	if d.Recorder != nil && !d.Recorder.Clean() {
		switch {
		case !d.Recorder.Present:
			parts = append(parts, "Config recorder: not present")
		case !d.Recorder.Recording:
			parts = append(parts, "Config recorder: present but not recording")
		default:
			parts = append(parts, "Config recorder: recording scope or role differs from a fresh compile")
		}
	}
	if d.DeliveryChannel != nil && !d.DeliveryChannel.Clean() {
		if !d.DeliveryChannel.Present {
			parts = append(parts, fmt.Sprintf("Config delivery channel: not present (expected %q)",
				d.DeliveryChannel.Bucket))
		} else {
			parts = append(parts, fmt.Sprintf("Config delivery channel: delivers to the wrong bucket "+
				"(expected %q)", d.DeliveryChannel.Bucket))
		}
	}
	if d.ConformancePack != nil && !d.ConformancePack.Clean() {
		if !d.ConformancePack.Present {
			parts = append(parts, fmt.Sprintf("conformance pack %q: not present", d.ConformancePack.Name))
		} else {
			parts = append(parts, fmt.Sprintf("conformance pack %q: deployed parameters differ from a "+
				"fresh compile", d.ConformancePack.Name))
		}
	}
	return &evidence.RecordError{
		Message:  "the detective layer does not match what this environment profile describes. " + strings.Join(parts, "; "),
		Action:   "config:DescribeConfigurationRecorders",
		Resource: "the account's AWS Config setup",
		Remediation: "re-run `automat vend` with this environment profile to re-ensure the recorder, " +
			"delivery channel, and conformance pack; every one of these is idempotent, so a re-vend " +
			"corrects drift in place rather than duplicating anything",
	}
}

// proceduralDriftError is the RecordError a procedural-layer drift record
// carries. Called only when !procedural.Clean(), so at least one stub is
// missing, empty, or stale.
func proceduralDriftError(r *verify.ProceduralReport) *evidence.RecordError {
	var missing, empty, stale []string
	for _, s := range r.Stubs {
		switch {
		case !s.Present:
			missing = append(missing, fmt.Sprintf("%q", s.FileName))
		case s.Empty:
			empty = append(empty, fmt.Sprintf("%q", s.FileName))
		case s.StaleChecked && s.Stale:
			stale = append(stale, fmt.Sprintf("%q", s.FileName))
		}
	}
	var parts []string
	add := func(names []string, what string) {
		if len(names) > 0 {
			parts = append(parts, what+": "+strings.Join(names, ", "))
		}
	}
	add(missing, "never written")
	add(empty, "present but never filled in")
	add(stale, "present but stale against its declared frequency")

	return &evidence.RecordError{
		Message: "the procedural layer does not match what this environment profile describes. " +
			strings.Join(parts, "; "),
		// Action is deliberately empty: schema/evidence-manifest-v1.schema.json
		// documents it as "the AWS action that was denied or failed", and this
		// finding comes from a local file read, not an AWS call.
		Resource: "the local attestation-stub directory",
		Remediation: "a missing stub is created by re-running `automat vend` with this environment " +
			"profile; an empty or stale one requires an operator to actually describe how the " +
			"practice is implemented and evidenced — automat cannot write that content for them, " +
			"only create the file for them to write it into",
	}
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
