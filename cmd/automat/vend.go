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

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/catalog"
	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/config"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/evidence"
	"github.com/scttfrdmn/automat/internal/org"
	"github.com/scttfrdmn/automat/internal/version"
)

// Round-trip patterns for the four values `vend` accepts on the command line and
// then writes into a record a person reads back (CLAUDE.md rule 8).
//
// Not injection prevention — argument construction is the CLI's problem and stays
// there. These four are refused at the boundary because automat *records* them:
// the account name reaches the plan, the evidence record, and the birth
// certificate; the email is the account's permanent key; the OU id and the
// create-account request id are what an operator types back into `--ou` and
// `--resume`. A value carrying a quote makes a record suggest a different command
// than the one it appears to, and a value carrying whitespace cannot be
// double-clicked, so it gets retyped and gets retyped wrong.
//
// The evidence and schema layers state the same classes over the same values
// (internal/evidence's reProse, reAccountID, reOUID, reRoundTripID). Stating them
// here too is rule 8's "both layers": a value refused only at write time is a
// value that has already been sent to AWS.
var (
	// AWS permits 50 characters in an account name. Interior spaces allowed —
	// "Genomics Lab" is what an account is really called — leading and trailing
	// refused, for the reason org.validOUName refuses them: a name that reads as
	// one thing and compares as another breaks every later find-by-name.
	reVendName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,48}[A-Za-z0-9._-])?$`)
	// The same address class internal/bundle applies, and deliberately no `%`:
	// this string is rendered with printf in several places, and a `%` in a value
	// is one refactor away from being read as a verb.
	reVendEmail = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$`)
	reVendOUID  = regexp.MustCompile(`^(ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|r-[0-9a-z]{4,32})$`)
	// A CreateAccountRequestId as AWS mints it (car-…), bounded to what the
	// evidence layer will accept in request_id so a value cannot be taken here and
	// refused at the moment it becomes the only handle on an in-flight create.
	reVendRequestID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
)

// newVendCmd builds `automat vend` — DESIGN §7.
//
// # What this build does and does not do
//
// Steps 1 to 4 and step 6: resolve the environment profile to a compiled control
// set, create the account, place it in the OU, ensure the OU's service control
// policies, write the evidence manifest, print the birth certificate.
//
// Step 5 — the in-child baseline work — is NOT performed, and it is reported
// rather than omitted. There is no internal/baseline package and no Config,
// Account Management, or IAM-write interface in internal/awsapi, so a Config
// recorder, a conformance pack, region enablement, attestation stubs, and the
// in-account automation role are all out of reach of this binary. A vend that
// silently skipped them would produce an account an operator believes has a
// detective baseline, which is the failure mode the whole evidence chain exists to
// prevent: the plan says so, the applied output says so, and the manifest carries
// a parked baseline-apply record saying so.
//
// # The one thing a first-vend plan cannot tell you
//
// The packer needs the in-account automation role's ARN, because
// baseline-protection's Deny statements exempt that role and rendering the
// placeholder literally would produce a condition matching no principal — an
// exemption that silently does not exist (compilesets.renderCondition). The ARN
// contains the account id, and a first vend's plan does not have one: the account
// does not exist yet. So the plan reports the policy set as unknown-but-would-
// happen rather than inventing an ARN, the same way org.EnsurePolicySet reports an
// attachment whose policy does not exist yet. A re-vend, a resume, and an adopted
// account all know the id and pack normally.
func newVendCmd(g *globals) *cobra.Command {
	var (
		profilePath string
		name        string
		email       string
		ouID        string
		resume      string
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:   "vend",
		Short: "Create an account with its controls attached before anyone can use it",
		Long: "Vends one AWS member account from an environment profile: creates it, moves it\n" +
			"into the target OU, and ensures the OU's service control policies match the\n" +
			"compiled control sets the profile names. Controls attach before the account is\n" +
			"handed to anyone, which is what makes \"born compliant\" a claim the evidence\n" +
			"manifest can back.\n\n" +
			"Every step is create-or-verify, so a second run writes nothing. A run that fails\n" +
			"after the account exists PARKS rather than aborting: the account is recorded, and\n" +
			"`automat vend --resume <request-id>` continues it. Re-running `vend` without\n" +
			"--resume is also safe — an account is found by its root email, which belongs to\n" +
			"exactly one AWS account — but --resume is the handle for a create that was still\n" +
			"in flight.\n\n" +
			"This build performs no in-child baseline work (DESIGN §7 step 5): no Config\n" +
			"recorder, no conformance pack, no region enablement, no attestation stubs, and no\n" +
			"in-account automation role. The plan and the evidence manifest both say so.\n\n" +
			"--dry-run prints the plan and stops. Note that --profile is the AWS credential\n" +
			"profile, as everywhere else; the environment profile is --environment-profile.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgCtx, err := g.orgContext()
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			// Every document check first, before a single AWS client is built. Not
			// an optimization: an unresolvable obligation reference, a profile that
			// will not validate, and a permitted set that intersects the control
			// sets to nothing are all refusals that must arrive while the plan is
			// still text on a screen (Q14's E5), and a refusal that waited for
			// credentials would arrive after the operator had gone to fetch them.
			in, err := loadVendInput(vendFlags{
				profilePath: profilePath,
				name:        name,
				email:       email,
				ouID:        ouID,
				resume:      resume,
			}, orgCtx)
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
			vendAPI, err := g.orgVendClient(ctx, region, profile)
			if err != nil {
				return err
			}
			// The policy half runs on its own client because in the MEMBER state it
			// runs on its own credential (DESIGN §5). No init client is built here,
			// and that absence is the point: `vend` holds no capability to create an
			// organization or enable a policy type.
			policyAPI, err := g.orgPolicyClient(ctx, region, profile)
			if err != nil {
				return err
			}

			ident, err := stsAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return awsapi.Denied(err, "sts:GetCallerIdentity", "", "",
					"run `automat login`, or set AWS_PROFILE to a profile with valid credentials; "+
						"automat will not create an account without knowing which account is vending "+
						"it — that identity becomes the automat:vended-by tag every later condition "+
						"reads")
			}
			caller := &callerIdentity{
				AccountID: aws.ToString(ident.Account),
				ARN:       aws.ToString(ident.Arn),
			}

			out := cmd.OutOrStdout()
			// One clock read for the whole command. Every timestamp in the manifest
			// comes from it, so the records of one vend agree with each other rather
			// than reporting the drift between two API calls.
			now := time.Now().UTC().Format(time.RFC3339)
			in.Now = now

			plan := newVendEnsurer(g, vendAPI, policyAPI, org.ModePlan, caller.ARN)
			planned, err := runVendSteps(ctx, plan, readAPI, caller, in, now)
			if err != nil {
				return err
			}
			if err := renderActions(out, "Plan:", plan.Actions()); err != nil {
				return err
			}
			if err := renderVendWarnings(out, in, planned); err != nil {
				return err
			}
			if dryRun {
				if _, werr := fmt.Fprintln(out, "\nNothing was applied (--dry-run)."); werr != nil {
					return fmt.Errorf("write the plan: %w", werr)
				}
				return nil
			}

			apply := newVendEnsurer(g, vendAPI, policyAPI, org.ModeApply, caller.ARN)
			applied, aerr := runVendSteps(ctx, apply, readAPI, caller, in, now)

			// The manifest is written whether or not the vend succeeded, and before
			// the error is returned. A run that created an account and then failed to
			// attach a policy has produced the state that most needs recording, and
			// an operator who is handed only the error has an account nobody wrote
			// down.
			manifestPath, werr := writeVendEvidence(in, applied)
			if werr != nil {
				if aerr != nil {
					return fmt.Errorf("%w (and the evidence manifest could not be written: %v)", aerr, werr)
				}
				return werr
			}

			if aerr != nil {
				if rerr := renderActions(cmd.ErrOrStderr(), "Applied before the failure:",
					apply.Actions()); rerr != nil {
					return fmt.Errorf("%w (and the partial-progress report could not be "+
						"written: %v)", aerr, rerr)
				}
				return vendFailure(aerr, applied, manifestPath)
			}

			if err := renderActions(out, "Applied:", apply.Actions()); err != nil {
				return err
			}
			if err := renderVendWarnings(out, in, applied); err != nil {
				return err
			}
			if !apply.Changed() {
				if _, werr := fmt.Fprintln(out,
					"\nNothing needed changing; the account was already vended."); werr != nil {
					return fmt.Errorf("write the result: %w", werr)
				}
			}
			return renderBirthCertificate(out, in, applied, manifestPath)
		},
	}

	f := cmd.Flags()
	f.StringVar(&profilePath, "environment-profile", "",
		"path to the environment profile to vend (required)")
	f.StringVar(&name, "name", "", "account name")
	f.StringVar(&email, "email", "",
		"account root email; defaults to the environment profile's or the config's email pattern")
	f.StringVar(&ouID, "ou", "",
		"destination OU id, overriding the environment profile's placement.target_ou")
	f.StringVar(&resume, "resume", "",
		"continue an earlier vend by its create-account request id")
	f.BoolVar(&dryRun, "dry-run", false, "print the plan and stop")

	return cmd
}

// vendFlags is what the operator typed, before any of it is checked.
type vendFlags struct {
	profilePath string
	name        string
	email       string
	ouID        string
	resume      string
}

// vendInput is one vend's resolved inputs: the documents, the narrowed control
// set, and the account identity. Everything here is known before automat speaks to
// AWS.
type vendInput struct {
	// Profile is the environment profile as loaded, and ContentHash is the hash
	// over its canonical content — the value the evidence record attests to.
	Profile     *envprofile.Profile
	ContentHash string
	// Sets are the resolved control sets, positionally aligned by
	// catalog.Resolved.
	Sets *catalog.Resolved
	// Narrowed is the merged control sets after the profile's permitted sets have
	// been intersected in. Warnings names members the profile asked for that the
	// control sets do not permit.
	Narrowed *compilesets.Narrowed
	// Obligations are the resolved obligation profiles the profile references.
	//
	// Kept past CheckObligations rather than discarded after it, because the birth
	// certificate cites these profiles by id and hash and must be able to say which
	// of them have not had their own citations retrieved (AUDIT-2 F1).
	Obligations envprofile.ObligationSet

	Name      string
	Email     string
	OUID      string
	RequestID string
	// Now is the one timestamp this vend's records carry.
	Now string
}

// vendState is what a pass over the vend steps learned. Both passes fill it; only
// the apply pass's is written to a manifest.
type vendState struct {
	OrgID               string
	ManagementAccountID string
	Partition           string
	RootID              string
	Destination         string

	AccountID   string
	RequestID   string
	Parent      string
	PolicyNames []string
	PolicyIDs   []string
	SCPARNs     []string
	Orphans     []string

	// PackWarnings are the packer's quota observations, which an operator three
	// vends from the policy limit needs before the vend that hits it.
	PackWarnings []string

	// Records are the evidence records this pass produced, in order. Empty for a
	// plan pass and for an apply pass that changed nothing — a manifest that grew
	// a record every time somebody re-ran an unchanged vend would bury the records
	// that mean something.
	Records []evidence.Record
	// Parked reports that the vend stopped somewhere recoverable.
	Parked bool
}

// loadVendInput resolves every document and refuses every refusable thing, with no
// AWS call and no credential.
//
// The order is DESIGN §7 step 1, and each step's failure is a plan-time refusal:
// load and validate the profile, resolve its control sets and obligation profiles,
// check the obligation references against the profiles themselves, then merge the
// control sets and narrow the merge by the profile's permitted behavior.
func loadVendInput(f vendFlags, orgCtx config.Context) (*vendInput, error) {
	if f.profilePath == "" {
		return nil, fmt.Errorf("no environment profile was given: pass " +
			"--environment-profile <file.json>.\n" +
			"That document is the whole input to a vend — which control sets to compile, which " +
			"regions and services to permit, where to place the account, and what the baseline " +
			"does. automat ships no default: a vend with a default posture would attach controls " +
			"nobody chose.\n" +
			"Note that --profile is the AWS credential profile, as in every other AWS tool " +
			"(DESIGN §7a)")
	}
	p, err := envprofile.Load(f.profilePath, envprofile.LoadOptions{})
	if err != nil {
		return nil, err
	}
	hash, err := p.ContentHash()
	if err != nil {
		return nil, fmt.Errorf("hashing environment profile %s: %w", f.profilePath, err)
	}

	sets, err := catalog.ResolveControlSets(p.ControlSets, catalog.Options{})
	if err != nil {
		return nil, err
	}
	obligationIDs := make([]string, 0, len(p.Obligations))
	for _, o := range p.Obligations {
		obligationIDs = append(obligationIDs, o.ID)
	}
	obligations, err := catalog.ResolveObligations(obligationIDs, catalog.Options{})
	if err != nil {
		return nil, err
	}
	if err = p.CheckObligations(obligations); err != nil {
		return nil, err
	}

	merged := compilesets.Merge(sets.Artifacts...)
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

	in := &vendInput{
		Profile: p, ContentHash: hash, Sets: sets, Narrowed: narrowed,
		Obligations: obligations,
	}
	if err := in.resolveIdentity(f, orgCtx); err != nil {
		return nil, err
	}
	return in, nil
}

// resolveIdentity settles the account's name, email, destination OU, and resume
// token, and refuses any of them that automat would not want to record.
func (in *vendInput) resolveIdentity(f vendFlags, orgCtx config.Context) error {
	in.RequestID = f.resume
	if in.RequestID != "" && !reVendRequestID.MatchString(in.RequestID) {
		return fmt.Errorf("--resume %q is not a create-account request id: AWS mints them in the "+
			"car-… form, and automat will not send a value it could not record — the request id is "+
			"the only handle on an in-flight create, so it has to survive a round trip through the "+
			"evidence manifest and back onto a command line", f.resume)
	}

	in.Name = strings.TrimSpace(f.name)
	switch {
	case in.Name == "" && in.RequestID == "":
		return fmt.Errorf("no account name was given: pass --name. The name is what an operator " +
			"reads in the console and in the plan; it is not how automat finds the account again " +
			"(AWS permits two accounts with the same name), which is what the root email is for")
	case in.Name != "" && !reVendName.MatchString(in.Name):
		return fmt.Errorf("--name %q is not an account name automat will record: letters, digits, "+
			"spaces, dots, underscores, and hyphens, up to 50 characters, with no leading or "+
			"trailing space. The name reaches the plan, the evidence record, and the birth "+
			"certificate a privileged reader acts on", f.name)
	}

	email, err := resolveVendEmail(f.email, in.Name, in.Profile, orgCtx)
	if err != nil {
		return err
	}
	in.Email = email

	in.OUID = firstNonEmpty(f.ouID, in.Profile.Placement.TargetOU, orgCtx.OU)
	switch {
	case in.OUID == "":
		return fmt.Errorf("no destination OU: the environment profile's placement.target_ou is " +
			"empty, the config file names no `ou`, and --ou was not passed.\n" +
			"A new account lands under the organization root (DESIGN §3, fact 4), and an account " +
			"left there carries none of the policies attached to the OU — so automat will not " +
			"create one it cannot place")
	case !reVendOUID.MatchString(in.OUID):
		return fmt.Errorf("%q is not an OU or root id: OU ids look like ou-abc1-12345678 and roots "+
			"like r-abc1. This value is recorded in the account's automat:ou tag, which the vendor "+
			"role's create condition reads, and it is printed for an operator to type back", in.OUID)
	}
	return nil
}

// resolveVendEmail settles the account's root email.
//
// Nothing else in automat substitutes envprofile.EmailNamePlaceholder, so this is
// where `research-admin+{name}@dept.edu` becomes an address. Two sources, profile
// first: the environment profile is the document under review, and the config file
// is a convenience for an operator vending many accounts from one mailbox.
func resolveVendEmail(flag, name string, p *envprofile.Profile, orgCtx config.Context) (string, error) {
	if flag != "" {
		if !reVendEmail.MatchString(flag) {
			return "", fmt.Errorf("--email %q is not an address automat will record: the local part "+
				"admits letters, digits, and ._+- and the domain must be dotted. The root email is "+
				"the account's permanent key (DESIGN §3, fact 11), so a value automat cannot read "+
				"back is a value it cannot find the account by on the next run", flag)
		}
		return flag, nil
	}

	var pattern, source string
	if p.Account != nil && p.Account.EmailPattern != "" {
		pattern, source = p.Account.EmailPattern, "the environment profile's account.email_pattern"
	} else if orgCtx.EmailPattern != "" {
		pattern, source = orgCtx.EmailPattern, "the config file's email_pattern"
	}
	switch {
	case pattern == "":
		return "", fmt.Errorf("no account email: pass --email, or set account.email_pattern in the " +
			"environment profile or email_pattern in the config file.\n" +
			"Each account needs a globally unique root address (DESIGN §3, fact 11), and it is the " +
			"key automat finds the account by on a re-run — so there is no default it could invent")
	case name == "":
		// Reachable only on a --resume with no --name, where the address is used
		// for message text rather than for a search. Refused rather than
		// substituted with an empty name, which would silently produce
		// `research-admin+@dept.edu`.
		return "", fmt.Errorf("cannot build an email from %s (%q) without an account name: pass "+
			"--name, or pass --email with the address the earlier run used", source, pattern)
	}

	if !strings.Contains(pattern, envprofile.EmailNamePlaceholder) {
		return "", fmt.Errorf("%s is %q, which contains no %s: every account needs its own address, "+
			"and a pattern with no placeholder produces the same one every time — the second vend "+
			"would be refused by AWS as a duplicate", source, pattern, envprofile.EmailNamePlaceholder)
	}
	// The name is substituted, not sanitized: a name that would produce an
	// unreadable address is refused rather than quietly rewritten, because the
	// operator has to be able to predict what mailbox their mail lands in.
	addr := strings.ReplaceAll(pattern, envprofile.EmailNamePlaceholder, strings.ReplaceAll(name, " ", "-"))
	if !reVendEmail.MatchString(addr) {
		return "", fmt.Errorf("%s (%q) with account name %q produces %q, which is not an address "+
			"automat will record. Spaces in the name become hyphens; anything else the pattern "+
			"needs, pass with --email", source, pattern, name, addr)
	}
	return addr, nil
}

// newVendEnsurer builds the Ensurer for one pass.
//
// No Init client, ever: `vend` cannot create an organization or enable a policy
// type, and the way that is enforced is that it never holds the interface (see
// internal/awsapi/api.go). Credential is Native because in MANAGEMENT and
// STANDALONE the caller's own identity does this work; the MEMBER path assumes the
// vendor role and is internal/broker's job in Phase 3, at which point this is
// where org.Brokered arrives.
// The sleep hook is threaded from globals rather than left at the package default
// because `vend` is the first command that waits: CreateAccount is asynchronous, so
// a test of it either injects a no-op wait or spends the real interval per poll per
// case. Nil in production, which is the default five-second interval.
func newVendEnsurer(g *globals, vendAPI awsapi.OrgVendAPI, policyAPI awsapi.OrgPolicyAPI,
	mode org.Mode, principal string) *org.Ensurer {
	return &org.Ensurer{
		Vend:       vendAPI,
		Policy:     policyAPI,
		Mode:       mode,
		Credential: org.Native,
		Principal:  principal,
		Sleep:      g.sleep,
	}
}

// runVendSteps is DESIGN §7, run identically in plan and apply mode.
//
// The ordering is the security property and it is this command's job rather than
// the ensure functions' (org.EnsurePolicyAttachment's doc says so): the policy type
// is confirmed enabled before anything is attached, the account is placed in the OU
// before policies are ensured on that OU, and baseline-protection goes last in the
// policy set (Q13).
func runVendSteps(ctx context.Context, e *org.Ensurer, read awsapi.OrgAPI,
	caller *callerIdentity, in *vendInput, now string) (*vendState, error) {
	st := &vendState{Partition: partitionOf(caller.ARN)}

	if err := describeVendOrg(ctx, read, caller, st); err != nil {
		return st, err
	}
	if err := requireSCPEnabled(ctx, read, caller, st); err != nil {
		return st, err
	}
	if err := resolveDestination(ctx, e, read, in, st); err != nil {
		return st, err
	}

	// Steps 2 and 3: create, then place. Both before any policy work, because a
	// policy ensured against the OU governs an account only once the account is in
	// it, and the ordering that fails safe is the one where the account is late
	// rather than the controls.
	acct, _, err := e.EnsureAccount(ctx, org.AccountSpec{
		Name:  in.Name,
		Email: in.Email,
		// in.OUID, not st.Destination: the tag names the delegated OU the grant's
		// StringEquals pins, while st.Destination below is where the account is
		// placed. They differ whenever placement.ou_path is set. See vendCreateTags.
		Tags:      vendCreateTags(caller, in.OUID),
		RequestID: in.RequestID,
		// The root and the destination, which are the two places an account a
		// previous run created can be: a create lands it under the root (DESIGN §3,
		// fact 4) and a run that got as far as the move left it in the OU.
		SearchParents: []string{st.RootID, st.Destination},
	})
	st.AccountID, st.RequestID, st.Parent = acct.ID, acct.RequestID, acct.Parent
	if in.RequestID != "" && st.RequestID == "" {
		st.RequestID = in.RequestID
	}
	if err != nil {
		// A create whose request id is known is resumable even though it failed:
		// the account may well exist, and the quota has been consumed either way.
		if st.RequestID != "" {
			st.park(in, caller, now, evidence.OpAccountCreate, err,
				"re-run: automat vend --environment-profile "+in.Profile.Meta.ID+
					" --resume "+st.RequestID)
			return st, err
		}
		return st, err
	}

	if st.AccountID != "" {
		if _, perr := e.EnsurePlacement(ctx, st.AccountID, st.Destination); perr != nil {
			st.park(in, caller, now, evidence.OpAccountMove, perr, vendResumeHint(in, st))
			return st, perr
		}
		st.Parent = st.Destination
	}
	st.recordAccountSteps(e, in, caller, now)

	// Step 4. The pack needs the account id, so this is the earliest point it can
	// happen; see the command's doc comment for why a plan without one reports
	// rather than guesses.
	specs, err := vendPolicySpecs(e, in, st)
	if err != nil {
		return st, err
	}
	res, err := e.EnsurePolicySet(ctx, st.Destination, specs)
	st.PolicyIDs, st.Orphans = res.IDs, res.Orphans
	for _, spec := range specs {
		st.PolicyNames = append(st.PolicyNames, spec.Name)
	}
	st.SCPARNs = st.policyARNs()
	if err != nil {
		st.park(in, caller, now, evidence.OpSCPEnsure, err, vendResumeHint(in, st))
		return st, err
	}
	st.recordSCPStep(e, in, caller, now, specs)

	// Step 5, reported rather than performed. See the command's doc comment.
	recordStepFiveIsMissing(e, in)
	st.recordBaselineIsMissing(e, in, caller, now)
	return st, nil
}

// describeVendOrg reads the organization automat is vending into.
//
// The management account id and the organization id are needed for the policy ARNs
// the evidence record carries: org.EnsurePolicy returns a policy *id*, and
// enforcement.scp_arns is an ARN list, so the ARN is assembled here from facts read
// at vend time rather than from a template with a hardcoded partition.
func describeVendOrg(ctx context.Context, read awsapi.OrgAPI, caller *callerIdentity, st *vendState) error {
	out, err := read.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		if awsapi.IsNotInOrganization(err) {
			return fmt.Errorf("account %s is not in an organization, so there is nothing to vend "+
				"into: an account is created *by* an organization's management account or by a role "+
				"in it.\n"+
				"Run `automat init` to create one from this account, or `automat setup --request` if "+
				"this account should be a member of somebody else's", caller.AccountID)
		}
		return awsapi.Denied(err, "organizations:DescribeOrganization", "", caller.ARN,
			"grant organizations:DescribeOrganization to "+caller.ARN+"; automat records the "+
				"organization id in every evidence record and assembles policy ARNs from it, and "+
				"it will not write a record naming an organization it could not read")
	}
	if out.Organization == nil {
		return fmt.Errorf("describing the organization: AWS returned no organization and no error")
	}
	st.OrgID = aws.ToString(out.Organization.Id)
	st.ManagementAccountID = aws.ToString(out.Organization.MasterAccountId)

	rootID, err := org.RootID(ctx, read)
	if err != nil {
		return awsapi.Denied(err, "organizations:ListRoots", "organization "+st.OrgID, caller.ARN,
			"grant organizations:ListRoots to "+caller.ARN+"; the root is where a new account lands "+
				"before it is moved, so automat cannot find an account a previous run created "+
				"without it")
	}
	st.RootID = rootID
	return nil
}

// requireSCPEnabled is the vend precondition that has no other guard.
//
// A vend into a root with the service control policy type disabled succeeds at
// every call and enforces nothing (org.SCPEnabled's doc: "the one failure in this
// package that produces a green run and an unprotected account"). Checked before
// the account is created rather than before the policies are attached, because the
// refusal is only cheap while there is no account to explain.
func requireSCPEnabled(ctx context.Context, read awsapi.OrgAPI, caller *callerIdentity, st *vendState) error {
	on, err := org.SCPEnabled(ctx, read)
	if err != nil {
		return awsapi.Denied(err, "organizations:ListRoots", "organization "+st.OrgID, caller.ARN,
			"grant organizations:ListRoots to "+caller.ARN+"; automat will not vend without "+
				"confirming that service control policies are enforced, and this is the call that "+
				"says whether they are")
	}
	if !on {
		return fmt.Errorf("the service control policy type is not ENABLED on root %s of organization "+
			"%s, so automat will not vend into it.\n"+
			"In that state creating a policy succeeds, attaching it succeeds, and nothing is "+
			"enforced — a green vend and an unprotected account. It is also the state an "+
			"organization prepared by hand is often in.\n"+
			"Run `automat init` from the management account (%s) to enable it; every step of that "+
			"command is create-or-verify, so it is safe against an organization that already "+
			"exists. A root reporting PENDING_ENABLE is not yet enforcing either — wait for it to "+
			"finish and re-run", st.RootID, st.OrgID, st.ManagementAccountID)
	}
	return nil
}

// resolveDestination settles the OU the account is placed into, applying the
// profile's placement.ou_path below placement.target_ou.
//
// create_intermediate_ous is honored rather than assumed. When it is false and the
// path does not already exist, this refuses instead of creating: the field exists so
// an institution can say that OU creation is central IT's to do, and a vend that
// created them anyway would be answering a question the document already answered.
// The probe is a plan-mode Ensurer over the same client, so the check is the same
// code that would do the work.
func resolveDestination(ctx context.Context, e *org.Ensurer, read awsapi.OrgAPI,
	in *vendInput, st *vendState) error {
	st.Destination = in.OUID
	path := in.Profile.Placement.OUPath
	if len(path) == 0 {
		return nil
	}

	if !in.Profile.Placement.CreateIntermediateOUs {
		probe := &org.Ensurer{Vend: e.Vend, Mode: org.ModePlan, Credential: org.Native, Principal: e.Principal}
		if _, actions, err := probe.EnsureOUPath(ctx, in.OUID, path); err != nil {
			return err
		} else if missing := plansOUCreation(actions); missing != "" {
			return fmt.Errorf("environment profile %s places accounts at %s below OU %s, and %q does "+
				"not exist — but the profile sets create_intermediate_ous to false, so automat will "+
				"not create it.\n"+
				"Either have whoever administers the organization create the OU path, or set "+
				"create_intermediate_ous to true in the profile. The field is there so that OU "+
				"creation can be central IT's to do, and a vend that created the OU anyway would "+
				"overrule the document it was given",
				in.Profile.Meta.ID, strings.Join(path, "/"), in.OUID, missing)
		}
	}

	dest, _, err := e.EnsureOUPath(ctx, in.OUID, path)
	if err != nil {
		return err
	}
	if dest == "" {
		// EnsureOUPath returns an empty id when a plan could not read below an OU
		// it would have created. The account is then planned into the OU the
		// profile names, which is where an apply would also start.
		if e.Mode == org.ModeApply {
			return fmt.Errorf("resolving %s below OU %s produced no OU id, which should be "+
				"impossible in an apply. Report this", strings.Join(path, "/"), in.OUID)
		}
		return nil
	}
	st.Destination = dest
	return nil
}

// plansOUCreation returns the name of the first OU the actions say would be
// created, or "" if the whole path already exists.
func plansOUCreation(actions []org.Action) string {
	for _, a := range actions {
		if a.Kind != "organizational unit" {
			continue
		}
		if a.Verb == org.VerbCreate || a.Verb == org.VerbUnknown {
			return a.Name
		}
	}
	return ""
}

// vendCreateTags are the tags applied AT CREATION, and there are exactly two
// because there can only be two.
//
// automat:vended-by and automat:ou are read by conditions — the vendor role's
// CreateAccount grant requires both as request tags, and MoveAccount requires
// vended-by on the account (internal/bundle/role.go). A tag a condition reads must
// not be writable by the principal the condition constrains, so they can be set
// only here, through aws:RequestTag, where the value is fixed by the grant rather
// than chosen at call time.
//
// vended-by is the VENDING account's id, not the vended one and not the literal
// "automat": that is what makes an account attributable to the member account whose
// delegation created it (internal/bundle/role.go:169, DESIGN §7a).
//
// # automat:ou is the DELEGATED OU, not the OU the account lands in
//
// These are the same value until placement.ou_path is non-empty, and then they are
// not, which is how AUDIT-2 found this: vend tagged with st.Destination — the
// resolved nested OU — while role.go:170 renders the condition as
// StringEquals aws:RequestTag/automat:ou: '<TargetOU>', a literal fixed when the
// bundle was generated. Every vend with an ou_path would have been denied in a real
// organization, and passed the suite because the fake compared tag keys only.
//
// The delegated OU is the right value on its own terms, not just the permitted one:
//
//   - The grant CANNOT be widened to the subtree. OU ids are opaque
//     (ou-<root>-<random>), so no StringLike pattern expresses "an OU below this
//     one" — the subtree relationship lives in the ARN path, which aws:RequestTag
//     compares as an unstructured string. A condition that admitted arbitrary sub-OU
//     ids would be admitting arbitrary strings.
//   - A per-sub-OU value would be WRONG BY DESIGN. The tag is immutable after
//     creation (it is deliberately absent from role.go's mutableTagKeys), while
//     MoveAccountsIntoTheDelegatedSubtreeOnly permits moving the account anywhere in
//     the subtree. A tag naming the leaf OU is stale after the first permitted move;
//     a tag naming the subtree root stays true for the account's whole life.
//
// So automat:ou answers "under which delegation was this account vended", which is
// the question the condition is asking, and which of the subtree's OUs it currently
// sits in is answered by ListParents. Where the account actually landed reaches the
// operator through the birth certificate and the evidence manifest, both of which
// record st.Destination.
//
// DESIGN §14's other three tags — automat:artifact-id, automat:artifact-sha256,
// automat:version — are the mutable set, written after the account exists, and
// automat cannot write them yet: nothing in internal/org tags an account after
// creation. Reported through recordStepFiveIsMissing's sibling rather than dropped.
func vendCreateTags(caller *callerIdentity, delegatedOU string) map[string]string {
	return map[string]string{
		"automat:vended-by": caller.AccountID,
		"automat:ou":        delegatedOU,
	}
}

// vendPolicySpecs packs the narrowed control set into policy specs, in the order
// EnsurePolicySet must see them.
//
// # baseline-protection last (Q13)
//
// baseline-protection's BP.IAM-1 denies iam:Attach*/Delete*/Detach*/Put*/Update* on
// the baseline roles and carries no exemption, not even for automat's own
// automation role — a role exempt from a Deny on its own permissions can rewrite
// them. So the protection must attach after everything that establishes those
// roles. The packer bin-packs by size rather than by origin, so "last" is applied
// to the policies that CARRY a baseline-protection statement: a bin mixing origins
// sorts last, because it is protected either way and attaching it early is the
// error that matters.
//
// The order is preserved rather than sorted, so two runs of the same vend produce
// the same policy names in the same slots.
func vendPolicySpecs(e *org.Ensurer, in *vendInput, st *vendState) ([]org.PolicySpec, error) {
	if st.AccountID == "" {
		// A first vend's plan. See the command's doc comment: the automation role's
		// ARN contains an account id that does not exist yet, and rendering the
		// placeholder literally would produce an exemption matching no principal.
		e.RecordUnknown("service control policy set",
			"cannot be checked: the account does not exist yet, so automat does not know the "+
				"in-account automation role's ARN — and baseline-protection's Deny statements exempt "+
				"that role, so the policies cannot be rendered without it. They would be created and "+
				"attached to "+st.Destination+" once the account exists; re-run the plan against the "+
				"vended account to see them")
		return nil, nil
	}

	packed, err := compilesets.Pack(in.Narrowed.Merged, compilesets.PackOptions{
		NamePrefix:        "automat-" + in.Profile.Meta.ID,
		AutomationRoleARN: in.automationRoleARN(st),
	})
	if err != nil {
		return nil, err
	}
	st.PackWarnings = packed.Warnings

	specs := make([]org.PolicySpec, 0, len(packed.Policies))
	var protective []org.PolicySpec
	for _, pol := range packed.Policies {
		spec := org.PolicySpec{
			Name:     pol.Name,
			Document: pol.Document,
			Description: "compiled by automat " + version.Version + " from environment profile " +
				in.Profile.Meta.ID,
		}
		if carriesBaselineProtection(pol.Statements) {
			protective = append(protective, spec)
			continue
		}
		specs = append(specs, spec)
	}
	return append(specs, protective...), nil
}

// carriesBaselineProtection reports whether any statement in the policy came from
// the baseline-protection control set. Origins are "artifact-id:control-id".
func carriesBaselineProtection(statements []compilesets.Statement) bool {
	for _, st := range statements {
		for _, origin := range st.Origins {
			if strings.HasPrefix(origin, catalog.BaselineProtectionID+":") {
				return true
			}
		}
	}
	return false
}

// automationRoleARN is the ARN the packer substitutes for
// artifact.AutomationRolePlaceholder.
//
// Built from the vended account's id and the profile's automation-role name. The
// role does not exist yet in this build — step 5 creates it — and the ARN is still
// correct: an ArnNotLike condition naming a role that does not exist exempts
// nobody, which is strictly the safe direction, and the same policy starts
// exempting the role the moment it is created under that name. What must not happen
// is rendering the placeholder, which would exempt nobody permanently while looking
// like an exemption.
func (in *vendInput) automationRoleARN(st *vendState) string {
	return "arn:" + st.Partition + ":iam::" + st.AccountID + ":role/" +
		in.Profile.Baseline.AutomationRole.RoleName()
}

// recordStepFiveIsMissing puts DESIGN §7 step 5 in the plan as an unknown rather
// than leaving it out.
//
// Every line here is something an operator reading a vend's output would otherwise
// assume happened. The detail names what is missing in the code rather than only in
// the account, because the operator's next question is whether a re-run would fix it.
func recordStepFiveIsMissing(e *org.Ensurer, in *vendInput) {
	p := in.Profile
	var missing []string
	if p.Baseline.ConfigRecorder.Enabled {
		missing = append(missing, "the Config recorder and delivery channel")
	}
	if len(configRuleNames(in)) > 0 {
		missing = append(missing, "the conformance pack from the control sets' config-rule set")
	}
	if p.Baseline.Regions != nil {
		missing = append(missing, "opt-in region enablement")
	}
	if p.Baseline.AutomationRole.ShouldCreate() {
		missing = append(missing, "the in-account automation role "+
			p.Baseline.AutomationRole.RoleName())
	}
	if attestationIDs(in) != nil {
		missing = append(missing, "attestation stubs for the procedural controls")
	}
	if p.Baseline.DisableOrgAccessRoleAfterVend {
		missing = append(missing, "disabling further use of "+envprofile.DefaultOrgAccessRole)
	}
	if len(missing) == 0 {
		missing = append(missing, "nothing this profile asks for")
	}
	e.RecordUnknown("in-child baseline (DESIGN §7 step 5)",
		"NOT PERFORMED by this build: "+strings.Join(missing, ", ")+". automat holds no Config, "+
			"Account Management, or IAM-write interface and no internal/baseline package, so it "+
			"cannot assume into the account at all. The account's preventive controls are real — the "+
			"service control policies above are attached at the OU — and its detective baseline does "+
			"not exist. Re-running will not change that; a later build will")

	// DESIGN §14's five account tags, of which this build writes two. Reported for
	// the same reason: an operator who reads §14 and then reads a vended account's
	// tags is owed the sentence explaining the difference.
	e.RecordUnknown("account tags automat:artifact-id, automat:artifact-sha256, automat:version",
		"NOT WRITTEN by this build: they are the mutable set DESIGN §14 applies after an account "+
			"exists, and nothing in internal/org tags an account after creation. The two tags that "+
			"conditions read — automat:vended-by and automat:ou — are set at creation, which is the "+
			"only moment they can be")
}

// vendResumeHint is the sentence a parked record ends with.
//
// It names --resume when there is a request id to resume and a plain re-run when
// there is not. Both are safe: the account is found by its root email, which
// belongs to exactly one AWS account anywhere. What must not be printed is a bare
// "re-run vend" at a point where the create was still in flight, because the
// natural reading of that is a second CreateAccount.
func vendResumeHint(in *vendInput, st *vendState) string {
	if st.RequestID != "" {
		return "re-run with --resume " + st.RequestID + ", which continues this account rather than " +
			"creating a second one"
	}
	return "re-run `automat vend` with the same environment profile and --name " + in.Name +
		"; the account is found by its root email, so nothing is created twice"
}

// park appends a parked evidence record.
//
// A parked or failed record REQUIRES a populated error (evidence's
// validateOutcomePairing), and the message is the remediation an operator acts on
// rather than a log line — including, where automat has one, the exact command that
// continues the vend.
func (st *vendState) park(in *vendInput, caller *callerIdentity, now string,
	op evidence.Operation, cause error, hint string) {
	st.Parked = true
	rerr := &evidence.RecordError{
		Message:     onelineError(cause),
		Remediation: hint,
	}
	if pe, ok := awsapi.AsPermissionError(cause); ok {
		rerr.Action, rerr.Resource = pe.Action, pe.Resource
		if pe.Grant != "" {
			rerr.Remediation = onelineError(fmt.Errorf("%s; then %s", pe.Grant, hint))
		}
	}
	st.Records = append(st.Records, evidence.Record{
		Timestamp:   now,
		Operation:   op,
		Outcome:     evidence.OutcomeParked,
		Operator:    evidence.Operator{ARN: caller.ARN, AccountID: caller.AccountID},
		RequestID:   st.RequestID,
		Target:      st.target(in),
		Artifact:    in.artifactRef(),
		EnvProfile:  in.Profile.Ref(in.ContentHash),
		Err:         rerr,
		ToolVersion: version.Version,
	})
}

// recordAccountSteps records the create and the move, and only when they changed
// something.
//
// A vend that found the account already in place has nothing to append: an
// append-only chain that grew two records every time somebody re-ran an unchanged
// vend would bury the records that mean something under the ones that do not.
func (st *vendState) recordAccountSteps(e *org.Ensurer, in *vendInput, caller *callerIdentity, now string) {
	if e.Mode != org.ModeApply || st.AccountID == "" {
		return
	}
	for _, a := range e.Actions() {
		if !a.Applied {
			continue
		}
		var op evidence.Operation
		switch {
		case a.Kind == "account" && a.Verb == org.VerbCreate:
			op = evidence.OpAccountCreate
		case a.Kind == "account placement" && a.Verb == org.VerbMove:
			op = evidence.OpAccountMove
		case a.Kind == "organizational unit" && a.Verb == org.VerbCreate:
			op = evidence.OpOUEnsure
		default:
			continue
		}
		st.Records = append(st.Records, evidence.Record{
			Timestamp:   now,
			Operation:   op,
			Outcome:     evidence.OutcomeSuccess,
			Operator:    evidence.Operator{ARN: caller.ARN, AccountID: caller.AccountID},
			RequestID:   st.RequestID,
			Target:      st.target(in),
			Artifact:    in.artifactRef(),
			EnvProfile:  in.Profile.Ref(in.ContentHash),
			ToolVersion: version.Version,
		})
	}
}

// recordSCPStep records the enforcement the account was born with.
//
// This is the record DESIGN §11 is really about: the region and service sets, and
// the ARNs of the policies that express them. Only written when something was
// attached or changed, for the reason recordAccountSteps gives.
func (st *vendState) recordSCPStep(e *org.Ensurer, in *vendInput, caller *callerIdentity,
	now string, specs []org.PolicySpec) {
	if e.Mode != org.ModeApply || len(specs) == 0 || !e.Changed() {
		return
	}
	st.Records = append(st.Records, evidence.Record{
		Timestamp:  now,
		Operation:  evidence.OpSCPEnsure,
		Outcome:    evidence.OutcomeSuccess,
		Operator:   evidence.Operator{ARN: caller.ARN, AccountID: caller.AccountID},
		RequestID:  st.RequestID,
		Target:     st.target(in),
		Artifact:   in.artifactRef(),
		EnvProfile: in.Profile.Ref(in.ContentHash),
		Enforcement: &evidence.Enforcement{
			SCPARNs:    st.SCPARNs,
			RegionSet:  members(in.Narrowed.Merged.RegionAllowlist),
			ServiceSet: members(in.Narrowed.Merged.ServiceAllowlist),
		},
		ToolVersion: version.Version,
	})
}

// recordBaselineIsMissing writes step 5's absence into the manifest, not only into
// the printed plan.
//
// Parked rather than omitted, and this is the honesty that matters most in the
// whole command: the manifest is the durable artifact an auditor reads, and a
// manifest carrying account-create and scp-ensure with no baseline-apply reads as a
// baseline that happened. Parked is also the accurate outcome — the work is
// genuinely outstanding — and it carries the required error, whose message says
// that no re-run completes it.
func (st *vendState) recordBaselineIsMissing(e *org.Ensurer, in *vendInput,
	caller *callerIdentity, now string) {
	if e.Mode != org.ModeApply || st.AccountID == "" || !e.Changed() {
		return
	}
	st.Records = append(st.Records, evidence.Record{
		Timestamp:  now,
		Operation:  evidence.OpBaselineApply,
		Outcome:    evidence.OutcomeParked,
		Operator:   evidence.Operator{ARN: caller.ARN, AccountID: caller.AccountID},
		RequestID:  st.RequestID,
		Target:     st.target(in),
		Artifact:   in.artifactRef(),
		EnvProfile: in.Profile.Ref(in.ContentHash),
		Err: &evidence.RecordError{
			Message: "the in-child baseline (DESIGN §7 step 5) was not performed: this build of " +
				"automat holds no Config, Account Management, or IAM-write interface, so it never " +
				"assumed into the account. No Config recorder, no conformance pack, no region " +
				"enablement, no attestation stubs, and no in-account automation role",
			Remediation: "the account's preventive controls are attached and real; its detective " +
				"baseline does not exist. Re-running this build will not change that. This record is " +
				"here so that nothing later mistakes the absence for a baseline that succeeded",
		},
		ToolVersion: version.Version,
	})
}

// target is the account this vend acted on, as an evidence target.
func (st *vendState) target(in *vendInput) *evidence.Target {
	return &evidence.Target{
		AccountID:   st.AccountID,
		AccountName: in.Name,
		OUID:        st.Destination,
	}
}

// policyARNs assembles the ARNs of the ensured policies.
//
// org.EnsurePolicy returns a policy id and never an ARN — an Organizations policy
// ARN is assigned at creation and encodes the organization — so the ARN is built
// here from the organization id, the management account, and the partition the
// caller's own ARN reports. Empty ids are skipped: a plan has them for policies
// that do not exist yet, and an evidence enforcement list admits no empty member.
func (st *vendState) policyARNs() []string {
	if st.OrgID == "" || st.ManagementAccountID == "" {
		return nil
	}
	out := make([]string, 0, len(st.PolicyIDs))
	for _, id := range st.PolicyIDs {
		if id == "" {
			continue
		}
		out = append(out, "arn:"+st.Partition+":organizations::"+st.ManagementAccountID+
			":policy/"+st.OrgID+"/service_control_policy/"+id)
	}
	return out
}

// artifactRef is the control artifact reference an evidence record carries, and it
// is nil more often than it should be.
//
// The evidence schema's `artifact` block names ONE document by id and content hash.
// A vend compiles a union — the profile's control sets plus baseline-protection,
// which catalog.ResolveControlSets always appends — so for any profile naming a
// control set of its own there are at least two, and no single one of them is "the
// control artifact this operation enforced".
//
// Rather than pick one, this fills the field only when the union is unambiguous and
// leaves it absent otherwise. Picking would be worse than absent: a record naming
// cmmc-l1 for a vend that also enforced a campus control set is a record an auditor
// would read as complete provenance. The environment profile's own id and content
// hash are recorded either way, and the profile names the control sets, so the
// chain is followable — one hop longer.
//
// This is a schema gap rather than a coding choice, and rule 6 says a schema change
// is asked for rather than made: `evidence-manifest/v1` needs either a repeated
// artifact block or a compiled-set hash before this field can be honest for a union.
func (in *vendInput) artifactRef() *evidence.DocRef {
	var only *artifact.Artifact
	for i, id := range in.Sets.IDs {
		if id == catalog.BaselineProtectionID {
			continue
		}
		if only != nil {
			return nil
		}
		only = in.Sets.Artifacts[i]
	}
	if only == nil {
		// The profile named nothing but baseline-protection, so it IS the artifact.
		for i, id := range in.Sets.IDs {
			if id == catalog.BaselineProtectionID {
				only = in.Sets.Artifacts[i]
			}
		}
	}
	if only == nil {
		return nil
	}
	return &evidence.DocRef{
		ID:            only.Meta.ID,
		ContentSHA256: only.Meta.ContentHash,
		SchemaVersion: only.SchemaVersion,
	}
}

// configRuleNames is every Config rule the resolved control sets ask for.
//
// Read but not deployed: it is what makes the step-5 report specific about which
// conformance pack is missing rather than saying only that one is.
func configRuleNames(in *vendInput) []string {
	var out []string
	for _, a := range in.Sets.Artifacts {
		for _, c := range a.Controls {
			for _, r := range c.ConfigRules {
				out = append(out, r.Name)
			}
		}
	}
	return out
}

// attestationIDs is every procedural control that wants an attestation stub, for
// the same reporting reason as configRuleNames.
func attestationIDs(in *vendInput) []string {
	var out []string
	for _, a := range in.Sets.Artifacts {
		for _, c := range a.Controls {
			if c.Attestation != nil {
				out = append(out, c.ID)
			}
		}
	}
	return out
}

// writeVendEvidence writes the manifest, and returns the path it wrote to.
//
// A manifest needs an account id — it is the manifest's own id and its account_id
// field — so a pass that created no account writes nothing and says so by returning
// an empty path. A pass that changed nothing appends nothing and also writes
// nothing: evidence.Manifest refuses an empty record list, and a chain that grew on
// every no-op run would be a chain nobody reads.
//
// The signer is nil. An unsigned local manifest is a valid document, and there is
// no signing-key setting in internal/config for this to read — automat ships no key
// ceremony (DESIGN §11a).
func writeVendEvidence(in *vendInput, st *vendState) (string, error) {
	if st == nil || st.AccountID == "" || len(st.Records) == 0 {
		return "", nil
	}
	// The directory is resolved ONCE, and the read and the write both go through
	// that descriptor. `local_dir` comes out of the environment profile, so its
	// components are a document's choice rather than the operator's, and
	// evidence.OpenDir is what keeps a symlink planted at one of them from sending
	// the manifest somewhere other than the path this function returns for printing.
	// AUDIT-2 H1: the two used to disagree, silently.
	dir, err := evidence.OpenDir(".", in.Profile.Baseline.Evidence.Dir(envprofile.DefaultEvidenceDir))
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	path := dir.Path(st.AccountID)

	m, err := dir.LoadOrNew(st.AccountID, st.AccountID, st.OrgID, in.Now, nil)
	if err != nil {
		return "", fmt.Errorf("cannot open the evidence manifest for account %s: %w\n"+
			"The account exists either way. automat refuses to continue a chain it cannot read, "+
			"because a manifest rewritten from scratch over a damaged one is the one failure the "+
			"hash chain exists to make visible", st.AccountID, err)
	}
	for i := range st.Records {
		if _, aerr := m.Append(st.Records[i], nil); aerr != nil {
			return "", fmt.Errorf("cannot append the %s record for account %s: %w",
				st.Records[i].Operation, st.AccountID, aerr)
		}
	}
	if err := dir.Write(m, st.AccountID); err != nil {
		return "", err
	}
	return path, nil
}

// vendFailure turns a step failure into the error the operator sees.
//
// The distinction it draws is the one ROADMAP Phase 2 asks for. A failure BEFORE
// the account exists is an ordinary error: nothing was made and re-running is the
// obvious next step. A failure AFTER it exists is PARKED — the account is real, its
// controls may be partial, and the wrong next step is a bare re-run of a command
// whose first act is CreateAccount. So a parked vend says what exists, where the
// record is, and what continues it, and only then reports the cause.
func vendFailure(cause error, st *vendState, manifestPath string) error {
	if st == nil || st.AccountID == "" && st.RequestID == "" {
		return cause
	}
	var b strings.Builder
	b.WriteString("this vend is PARKED, not failed: ")
	switch {
	case st.AccountID != "":
		fmt.Fprintf(&b, "account %s exists", st.AccountID)
		if st.Parent != "" {
			fmt.Fprintf(&b, " under %s", st.Parent)
		}
	default:
		fmt.Fprintf(&b, "create-account request %s was accepted, so an account may exist", st.RequestID)
	}
	b.WriteString(".\n")
	if manifestPath != "" {
		fmt.Fprintf(&b, "Recorded in %s.\n", manifestPath)
	}
	if org.Parkable(cause) {
		b.WriteString("The remaining work is resumable: fix the cause below and re-run. " +
			"Do NOT run a fresh `vend` expecting it to start over — it would not, and it must not.\n")
	}
	b.WriteString("Cause: ")
	// Wrapped rather than formatted with %v: the cause is very often an
	// awsapi.PermissionError, and a caller that can no longer reach it through
	// errors.As has lost the action, the resource, and the grant that rule 7 exists
	// to carry. The prose goes through %s rather than becoming the format string,
	// because a path or an account name carrying a % must not be read as a verb.
	return fmt.Errorf("%s%w", b.String(), cause)
}

// renderVendWarnings prints what the narrowing and the packing observed.
//
// Warnings rather than errors, and printed rather than logged. An operator who
// wrote eu-west-1 into a profile and got an account that cannot reach eu-west-1 is
// owed the sentence explaining why at plan time; an operator three vends from the
// policy quota needs to know before the vend that hits it.
func renderVendWarnings(w io.Writer, in *vendInput, st *vendState) error {
	all := append(append([]string(nil), in.Narrowed.Warnings...), st.PackWarnings...)
	if len(st.Orphans) > 0 {
		all = append(all, "service control policies automat owns are attached to "+st.Destination+
			" and are not in this profile's set: "+strings.Join(st.Orphans, ", ")+
			". automat holds no DetachPolicy and cannot remove them; they are Deny policies, so they "+
			"remain in force and the account is more restricted than this profile asks for")
	}
	if len(all) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("\nWarnings:\n")
	for _, warn := range all {
		b.WriteString("  " + warn + "\n")
	}
	if _, err := fmt.Fprint(w, b.String()); err != nil {
		return fmt.Errorf("write the warnings: %w", err)
	}
	return nil
}

// renderBirthCertificate is DESIGN §7 step 6's second half: account id, OU, control
// artifact hash, enforcement summary.
//
// Everything printed here is also in the manifest. It is printed anyway because the
// manifest is for the auditor six months later and this is for the operator now,
// and because the hashes are what make the claim checkable — a birth certificate
// naming control sets without their hashes is a label.
func renderBirthCertificate(w io.Writer, in *vendInput,
	st *vendState, manifestPath string) error {
	if st.AccountID == "" {
		return nil
	}
	var b strings.Builder
	b.WriteString("\nBirth certificate:\n")
	line := func(label, value string) {
		if value == "" {
			return
		}
		fmt.Fprintf(&b, "  %-24s %s\n", label, value)
	}
	line("account", st.AccountID+" ("+in.Name+", "+in.Email+")")
	line("organization", st.OrgID)
	line("organizational unit", st.Destination)
	line("vended by", st.ManagementAccountID)
	line("environment profile", in.Profile.Meta.ID+" sha256:"+in.ContentHash)
	line("review by", in.Profile.ReviewBy)
	for i, id := range in.Sets.IDs {
		label := "control sets"
		if i > 0 {
			label = ""
		}
		line(label, id+" sha256:"+in.Sets.Artifacts[i].Meta.ContentHash)
	}
	for i, name := range st.PolicyNames {
		label := "service control policies"
		if i > 0 {
			label = ""
		}
		id := ""
		if i < len(st.PolicyIDs) && st.PolicyIDs[i] != "" {
			id = " (" + st.PolicyIDs[i] + ")"
		}
		line(label, name+id)
	}
	if len(st.PolicyNames) == 0 {
		line("service control policies", "none: these control sets carry no preventive statements")
	}
	line("permitted regions", enumerate(members(in.Narrowed.Merged.RegionAllowlist),
		"unconstrained by these control sets and this profile"))
	line("permitted services", enumerate(members(in.Narrowed.Merged.ServiceAllowlist),
		"unconstrained by these control sets and this profile"))
	for i, o := range in.Profile.Obligations {
		label := "obligations"
		if i > 0 {
			label = ""
		}
		// The unretrieved-citation marking, and it is IN the rendered line rather
		// than in a footnote (AUDIT-2 F1). docs/policy-caveat.md's whole argument is
		// that the rendered output is what gets forwarded and attached to an
		// agreement, without whatever page explained the caveat — so a birth
		// certificate that cites dfars-7012 by hash while that profile's own sources
		// are sixty-four zeros has to say so where the citation is.
		//
		// The hash printed is the ENVIRONMENT PROFILE's claim about the obligation
		// profile, which is a different question and also unverified (Q15: the
		// schema does not define what an obligation profile's content hash covers).
		// Both are stated, because a reader shown one hash has no way to tell how
		// many unchecked claims stand behind it.
		note := ""
		if facts, ok := in.Obligations[o.ID]; ok && !facts.ProvenanceIsComplete() {
			note = " — CITATIONS NOT RETRIEVED: this profile records " +
				strings.Join(facts.UnresolvedSources, ", ") +
				" from published identifiers, not from retrieved copies. Verify against the " +
				"primary source before relying on any date or clause number it states"
		}
		line(label, o.ID+" sha256:"+o.ContentSHA256+note)
	}
	line("detective baseline", "NOT APPLIED — DESIGN §7 step 5 is not in this build; the "+
		"manifest carries a parked baseline-apply record")
	line("evidence manifest", manifestPath)
	if st.RequestID != "" {
		line("create-account request", st.RequestID)
	}
	if _, err := fmt.Fprint(w, b.String()); err != nil {
		return fmt.Errorf("write the birth certificate: %w", err)
	}
	return nil
}

// members returns an allowlist's members, or nil when the axis is unconstrained.
// nil and empty mean different things everywhere in compilesets and they mean
// different things here: nil is "nobody constrained this", and an empty non-nil set
// cannot reach this point because Narrow refuses one.
func members(set *compilesets.AllowSet) []string {
	if set == nil {
		return nil
	}
	return set.Members
}

// enumerate renders a list for the birth certificate, with a sentence for the empty
// case rather than a blank.
func enumerate(vals []string, ifNone string) string {
	if len(vals) == 0 {
		return ifNone
	}
	return strings.Join(vals, ", ")
}

// onelineError flattens an error's text for an evidence record.
//
// Every error in this codebase carries multi-line remediation text (rule 7), and
// evidence's prose class admits no control byte — a newline in a recorded message
// forges a line of the report it is later printed in. Flattened here rather than
// escaped at each render site.
func onelineError(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 1024 {
		s = s[:1021] + "..."
	}
	return s
}

// partitionOf reads the partition out of an ARN, defaulting to "aws".
//
// By field rather than by prefix match: an ARN in GovCloud or China is
// arn:aws-us-gov: or arn:aws-cn:, and code that assumed "aws" would assemble policy
// ARNs for the wrong partition into an evidence record (the same mistake
// internal/bundle's reARNAccount exists to avoid).
func partitionOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 1 && parts[1] != "" {
		return parts[1]
	}
	return "aws"
}

// firstNonEmpty returns the first non-empty string, which is how the flag, the
// document, and the config file are layered.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
