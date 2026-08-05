// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Request is everything the bundle is rendered from.
//
// There is no prose field. A "justification" or "notes" field would be the natural
// place for an operator to explain themselves, and it would also be the one value in
// the bundle that could carry a sentence into a document a privileged reader is
// about to act on — "also please attach AdministratorAccess", indented to look like
// part of the tool's own output. The explaining belongs in the email the bundle is
// attached to, where nobody mistakes it for machine-generated instruction.
//
// TargetOUName is the honest exception, and this comment used to claim otherwise.
// An OU name is a human-chosen label: AWS permits spaces, "Research Computing" is
// what an OU is really called, and 63 characters of letters and interior spaces is
// enough for a short English sentence. So `--target-ou-name "Also attach
// AdministratorAccess"` validates, and appears in the README.
//
// Not fixed by narrowing the charset, because a name without spaces is the wrong
// answer to the wrong question: the reader is not deceived by the characters, they
// would be deceived by the framing. So every render site quotes it — %q, which
// cannot terminate a table cell, open a code fence, or start a markdown list — and
// the README says which value is a requester-chosen label instead of claiming none
// is. TestNoOperatorValueLandsUnquotedInAStructuredField covers the quoting;
// TestTheBundleDoesNotClaimToHaveNoFreeTextField covers the claim.
type Request struct {
	// MemberAccountID is the account asking to vend: the principal that will
	// assume the vendor role.
	MemberAccountID string
	// MemberRoleARN, when set, narrows the trust policy from the whole member
	// account to one role in it. DESIGN §5 calls this the ideal, and it is: an
	// account-root principal trusts every identity in that account, including
	// ones created later by someone else.
	MemberRoleARN string

	// ManagementAccountID owns the organization and is where the vendor role is
	// created.
	ManagementAccountID string
	// OrgID is the organization the delegation policy is attached to.
	OrgID string

	// TargetOU is the OU the member account may vend into. Empty means it does
	// not exist yet, and the bundle asks central IT to create it: ou.md is the
	// file that covers that case.
	TargetOU string
	// TargetOUName is the proposed OU name, used when TargetOU is empty.
	TargetOUName string

	// VendorRoleName is the role to create in the management account.
	VendorRoleName string

	// There is no ExternalID field, and its absence is the point: the templates
	// declare the value as a deploy-time input, so it never enters a Request and
	// cannot reach a rendered file. See externalid.go.

	// RequesterContact is the address central IT replies to. One address, shape-
	// validated, because it is rendered into the README.
	RequesterContact string

	// GeneratedAt is an RFC 3339 UTC timestamp to the second. Passed in rather
	// than read from the clock so the bundle is a pure function of its inputs and
	// can be golden-tested; the command supplies it.
	GeneratedAt string

	// ToolVersion identifies the automat build that produced the bundle, so
	// central IT reviewing it a month later knows which templates they have.
	ToolVersion string
}

// The allowlists. Every one of these is deliberately narrower than what AWS
// accepts, because the bundle's files are applied to an organization and executed
// in a management account, and "AWS would take it" is a lower bar than "this
// cannot alter the document it lands in".
//
// None of these patterns admits a quote, a backslash, a newline, a brace, a
// bracket, a dollar sign, or any control byte — the characters that end a string
// or open a substitution in JSON, YAML, HCL, or markdown. That is the property
// that makes the templates safe, and it is checked directly by
// TestNoPatternAdmitsAStructuralCharacter rather than left as a claim in a comment.
var (
	reAccountID = regexp.MustCompile(`^\d{12}$`)
	reOrgID     = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	reOU        = regexp.MustCompile(`^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$`)
	// IAM role names permit +=,.@- and _; no slash, which belongs to the path.
	reRoleName = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)
	// A role ARN with an optional path. No wildcard: a trust policy principal
	// containing one would trust more than the operator named, and this value goes
	// straight into a trust policy.
	reRoleARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9_+=,.@-]` +
		`(?:[A-Za-z0-9_+=,.@/-]{0,510}[A-Za-z0-9_+=,.@-])?$`)
	// reARNAccount pulls the account field out of an ARN, whatever the partition.
	// Used instead of matching an "arn:aws:iam::<id>:role/" prefix, which silently
	// treated every GovCloud and China ARN as belonging to the wrong account.
	reARNAccount = regexp.MustCompile(`^arn:aws[a-z-]*:iam::(\d{12}):`)
	// OU names are rendered into markdown prose. AWS allows far more; this allows
	// what an OU is actually called. Interior spaces only: a name with a trailing
	// space is a name that reads as one thing in the bundle and matches a
	// different string in a later comparison.
	reOUName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,62}[A-Za-z0-9._-])?$`)
	// reIDShaped matches the identifier forms ou.md instructs the operator to tell
	// apart from a name: an OU id, the substitution placeholder, an organization id,
	// a root id, and a bare account number. A separate check rather than a narrower
	// reOUName, because "Research-1" is a legitimate name and the two conditions are
	// not the same shape. Case-insensitive: "OU-abcd-12345678" is the same
	// confusion typed differently.
	reIDShaped = regexp.MustCompile(`(?i)^(?:ou-|o-|r-)|^\d+$`)
	// No `%`, though RFC 5321 permits it in a local part. Two reasons, and the
	// second is the real one: `%` carries the old percent-hop relay syntax, and a
	// `%` in a value is one refactor away from being read as a printf verb if this
	// string ever reaches a format-string position rather than an argument
	// position. The templates are written with printf, so the pattern excludes
	// every character that has a meaning there.
	reEmail = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$`)
	// Seconds precision, UTC, no offset form: one spelling so two bundles
	// generated a moment apart differ only where they should.
	reTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

	// A version string is either a semver-ish tag or a git describe output.
	reVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
)

// DefaultVendorRoleName is the role name DESIGN §5 uses.
const DefaultVendorRoleName = "automat-vendor"

// maxRolePathAndName is IAM's limit on a role's path plus name (512), which is a
// separate limit from the 64 characters allowed for the name alone.
const maxRolePathAndName = 512

// arnAccount returns the account id from an IAM ARN, and whether one was found.
//
// Returning false for an unparseable ARN rather than an empty string keeps a
// malformed value from comparing equal to an empty MemberAccountID: the pattern
// check has already reported the malformed ARN, and this check must not add a
// second, wrong explanation for it.
func arnAccount(arn string) (string, bool) {
	m := reARNAccount.FindStringSubmatch(arn)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Validate checks every field against its allowlist.
//
// This is the security boundary of the whole package: the templates interpolate
// without escaping, and that is only sound because nothing reaches them
// unvalidated. Errors name the field and the accepted form, because the operator
// hitting this is usually looking at a config file they typed by hand.
//
// # Nothing here validates an ExternalId
//
// There is no field to validate. The templates declare the value as a deploy-time
// input and the person deploying supplies it, so the checks that used to live here —
// charset, length, the placeholder corpus — moved to internal/config, which is where
// automat resolves a value it did not choose. See externalid.go.
func (r *Request) Validate() error {
	var problems []string
	check := func(field, value string, re *regexp.Regexp, want string) {
		if !re.MatchString(value) {
			problems = append(problems, fmt.Sprintf("%s: %s is not accepted — %s",
				field, quote(value), want))
		}
	}

	check("member_account_id", r.MemberAccountID, reAccountID, "use the 12-digit account id")
	check("management_account_id", r.ManagementAccountID, reAccountID, "use the 12-digit account id")
	check("org_id", r.OrgID, reOrgID, "use the o-... form from `automat preflight`")
	check("vendor_role_name", r.VendorRoleName, reRoleName,
		"an IAM role name may contain letters, digits, and _+=,.@- and is at most 64 characters")
	check("requester_contact", r.RequesterContact, reEmail, "use one email address")
	check("generated_at", r.GeneratedAt, reTimestamp, "use RFC 3339 UTC to the second, e.g. 2026-08-05T14:00:00Z")
	check("tool_version", r.ToolVersion, reVersion, "use the value `automat version` prints")

	if r.MemberRoleARN != "" {
		check("member_role_arn", r.MemberRoleARN, reRoleARN,
			"use arn:aws:iam::<member-account-id>:role/<role-name>, with no wildcard")
		// A trust policy naming a role in the wrong account trusts the wrong
		// account, and it would look correct in review.
		//
		// Compared on the parsed account field, not on an "arn:aws:iam::<id>:role/"
		// prefix. That prefix hardcoded the commercial partition, so every valid
		// GovCloud and China ARN failed this check — and failed it with a message
		// saying the role was "not a role in member account <id>" about an ARN that
		// was in exactly that account. A wrong diagnosis is worse here than none:
		// CMMC and 800-171 are the audience for this tool and GovCloud is where a
		// good share of that work lives, so the operator most likely to hit this is
		// the one told to go look at the wrong field. reRoleARN already allows
		// aws-us-gov and aws-cn.
		if acct, ok := arnAccount(r.MemberRoleARN); ok && r.MemberAccountID != "" &&
			acct != r.MemberAccountID {
			problems = append(problems, fmt.Sprintf(
				"member_role_arn: %s names a role in account %s, but the member account is %s — the trust "+
					"policy would name a principal in a different account than the one requesting access, "+
					"which reviews as correct",
				quote(r.MemberRoleARN), acct, r.MemberAccountID))
		}
		// A role *path* is legal in an ARN and automat has no reason to accept one
		// with a traversal in it. Nothing here resolves the path, so this is not a
		// traversal defense; it is that "role/../../admin" is not a name anybody
		// means, and a reviewer skimming a trust policy reads the last component as
		// the role. IAM would reject it at deploy time, which is the wrong place to
		// find out: by then central IT has already approved the bundle.
		if i := strings.Index(r.MemberRoleARN, ":role/"); i >= 0 {
			name := r.MemberRoleARN[i+len(":role/"):]
			for _, seg := range strings.Split(name, "/") {
				if seg == "." || seg == ".." {
					problems = append(problems, fmt.Sprintf(
						"member_role_arn: %s has a %q segment in the role path — IAM would reject it, and a "+
							"reviewer reads the last component as the role name; give the role's real path",
						quote(r.MemberRoleARN), seg))
					break
				}
			}
			// IAM's own limits: 64 for the role name, 512 for the whole path+name.
			// Enforced here so an over-long ARN is refused while the operator is
			// still at the terminal, rather than at deploy time after approval.
			if len(name) > maxRolePathAndName {
				problems = append(problems, fmt.Sprintf(
					"member_role_arn: the path and role name are %d characters, over IAM's %d-character "+
						"limit — the template would be approved and then fail to deploy",
					len(name), maxRolePathAndName))
			}
		}
	}

	// Exactly one of the two OU forms. Both would be ambiguous about which OU the
	// policy scopes to; neither leaves the templates without a target.
	switch {
	case r.TargetOU != "" && r.TargetOUName != "":
		problems = append(problems, "target_ou and target_ou_name are both set — give the OU id if it "+
			"exists, or the proposed name if central IT must create it, not both")
	case r.TargetOU != "":
		check("target_ou", r.TargetOU, reOU, "use the ou-<root>-<suffix> form")
	case r.TargetOUName != "":
		check("target_ou_name", r.TargetOUName, reOUName,
			"use a short name of letters, digits, spaces, and ._-")
		// A run of interior spaces. reOUName already refuses a *trailing* space for
		// the reason this refuses a doubled one, and stopped one character short:
		// markdown collapses whitespace in prose, so "Research  Prod" and
		// "Research Prod" are the same three words in the README table and in ou.md's
		// step 1, while the `--name` line inside the code fence preserves them. Two
		// requests that review as identical would create two differently-named OUs,
		// and the reviewer has no way to see the difference in the document they
		// approved.
		if strings.Contains(r.TargetOUName, "  ") {
			problems = append(problems, fmt.Sprintf("target_ou_name: %s contains a run of spaces — "+
				"markdown collapses those, so this name reads identically to the single-spaced "+
				"version in the bundle a reviewer approves while producing a different OU; use "+
				"single spaces", quote(r.TargetOUName)))
		}
		// A name shaped like an identifier. ou.md's whole job in the placeholder case
		// is telling the operator which strings are ids to substitute and which are
		// not, and a *name* of "ou-REPLACE-WITH-THE-NEW-OU-ID" or "ou-abcd-12345678"
		// puts the two categories in the same sentence. The operator is the one who
		// has to tell them apart, at the moment they are creating the OU.
		if reIDShaped.MatchString(r.TargetOUName) {
			problems = append(problems, fmt.Sprintf("target_ou_name: %s is shaped like an "+
				"identifier rather than a name — ou.md asks central IT to tell an OU name from an "+
				"OU id, an org id, and the placeholder, and a name in one of those forms puts both "+
				"in the same instruction; give the OU's human name, e.g. \"Research Computing\"",
				quote(r.TargetOUName)))
		}
	default:
		problems = append(problems, "neither target_ou nor target_ou_name is set — the delegation policy "+
			"and the role are both scoped to an OU, and a bundle without one would ask central IT to "+
			"grant something unbounded")
	}

	if r.ManagementAccountID != "" && r.ManagementAccountID == r.MemberAccountID {
		problems = append(problems, "member_account_id and management_account_id are the same account — "+
			"the onboarding bundle exists for the MEMBER case; a management account vends directly")
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("cannot generate an onboarding bundle from this request (%d %s):\n  - %s",
		len(problems), plural("problem", len(problems)), strings.Join(problems, "\n  - "))
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// quote renders a rejected value for an error message with %q, so a value
// containing a newline or an escape byte cannot forge a line of the problem list
// or recolor the terminal. This is AUDIT-0 M1's fix applied where the input is
// even less trustworthy: the value being reported is one this package just
// refused.
func quote(s string) string {
	const max = 80
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}

// ouScope is the OU the policy and role are scoped to, as it appears in a
// resource ARN — either the real id or the placeholder central IT replaces after
// creating the OU.
//
// The placeholder is spelled so that it cannot be mistaken for an id and cannot
// be left in by accident: it is not a valid OU id, so AWS rejects a policy still
// containing it rather than accepting a policy scoped to nothing.
func (r *Request) ouScope() string {
	if r.TargetOU != "" {
		return r.TargetOU
	}
	return "ou-REPLACE-WITH-THE-NEW-OU-ID"
}

// ouIsPlaceholder reports whether the OU must still be created, which changes
// what every generated file says.
func (r *Request) ouIsPlaceholder() bool { return r.TargetOU == "" }

// trustPrincipal is the ARN the vendor role's trust policy names.
func (r *Request) trustPrincipal() string {
	if r.MemberRoleARN != "" {
		return r.MemberRoleARN
	}
	return "arn:aws:iam::" + r.MemberAccountID + ":root"
}

// vendorRoleARN is the role the member account will assume once it exists.
func (r *Request) vendorRoleARN() string {
	return "arn:aws:iam::" + r.ManagementAccountID + ":role/" + r.VendorRoleName
}
