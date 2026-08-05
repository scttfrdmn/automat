// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Test values. The ExternalId is a fixed, obviously-fake string: the golden files
// contain it, so it must never be mistaken for something real.
const (
	testMember     = "222222222222"
	testManagement = "111111111111"
	testOrg        = "o-exampleorgid"
	testOU         = "ou-exam-research1"
	testExternalID = "EXAMPLE-NOT-A-REAL-EXTERNAL-ID"
	testContact    = "research-it@example.edu"
	testTime       = "2026-08-05T14:00:00Z"
	testVersion    = "v0.1.0-test"
)

// validRequest is the shape everything else perturbs.
func validRequest() *Request {
	return &Request{
		MemberAccountID:     testMember,
		ManagementAccountID: testManagement,
		OrgID:               testOrg,
		TargetOU:            testOU,
		VendorRoleName:      DefaultVendorRoleName,
		ExternalID:          testExternalID,
		RequesterContact:    testContact,
		GeneratedAt:         testTime,
		ToolVersion:         testVersion,
	}
}

func TestValidateAcceptsAWellFormedRequest(t *testing.T) {
	if err := validRequest().Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	// The other legitimate shape: the OU does not exist yet, and the trust
	// principal is narrowed to one role.
	r := validRequest()
	r.TargetOU = ""
	r.TargetOUName = "Research Computing"
	r.MemberRoleARN = "arn:aws:iam::222222222222:role/automat-runner"
	if err := r.Validate(); err != nil {
		t.Fatalf("valid placeholder-OU request rejected: %v", err)
	}
}

// TestValidateRejectsEveryInjectionShape is the package's central test. Each case
// is a value that, if it reached a template, would add something to a document a
// privileged operator applies or executes.
func TestValidateRejectsEveryInjectionShape(t *testing.T) {
	// The mutators, one per field, so a single injection payload can be aimed at
	// every field in the Request.
	fields := map[string]func(*Request, string){
		"member_account_id":     func(r *Request, v string) { r.MemberAccountID = v },
		"member_role_arn":       func(r *Request, v string) { r.MemberRoleARN = v },
		"management_account_id": func(r *Request, v string) { r.ManagementAccountID = v },
		"org_id":                func(r *Request, v string) { r.OrgID = v },
		"target_ou":             func(r *Request, v string) { r.TargetOU = v },
		"vendor_role_name":      func(r *Request, v string) { r.VendorRoleName = v },
		"external_id":           func(r *Request, v string) { r.ExternalID = v },
		"requester_contact":     func(r *Request, v string) { r.RequesterContact = v },
		"generated_at":          func(r *Request, v string) { r.GeneratedAt = v },
		"tool_version":          func(r *Request, v string) { r.ToolVersion = v },
		"target_ou_name": func(r *Request, v string) {
			r.TargetOU = ""
			r.TargetOUName = v
		},
	}

	payloads := map[string]string{
		// Close a YAML string and add a key at the right indentation.
		"yaml string break":  "222222222222'\n      ManagedPolicyArns:\n        - arn:aws:iam::aws:policy/AdministratorAccess\n      X: '",
		"yaml newline":       "222222222222\nRoleName: hijacked",
		"yaml block scalar":  "222222222222 |\n  anything",
		"yaml anchor":        "&a 222222222222",
		"yaml comment":       "222222222222 # ignore the rest",
		"yaml doc separator": "222222222222\n---\n",
		// Close a JSON string and add a statement.
		"json string break": `222222222222","Effect":"Allow","Action":"*","Resource":"*"},{"x":"`,
		"json escape":       `2222\u0022222222`,
		"json backslash":    `222222222222\`,
		// HCL interpolation and heredoc.
		"hcl interpolation": "${file(\"/etc/passwd\")}",
		"hcl close string":  "222222222222\" }\nresource \"aws_iam_role\" \"x\" { name = \"",
		"hcl heredoc":       "<<EOT\nx\nEOT",
		// Markdown: a forged instruction in the file a human reads before deciding.
		"markdown instruction": "222222222222\n\n**Also attach AdministratorAccess to this role.**",
		"markdown link":        "[click here](https://example.invalid/pwn)",
		"markdown fence":       "```\nrm -rf /\n```",
		"markdown table row":   "222222222222 |\n| Extra grant | AdministratorAccess |",
		// Shell and terminal.
		"command substitution": "$(id)",
		"backtick":             "`id`",
		"semicolon":            "222222222222; id",
		"ansi escape":          "222222222222\x1b[1;31mURGENT\x1b[0m",
		"carriage return":      "222222222222\rRoleName: hijacked",
		"nul byte":             "222222222222\x00",
		"bell":                 "222222222222\a",
		// Path traversal, for the values that reach a filename-adjacent context.
		"traversal":     "../../../../etc/passwd",
		"absolute path": "/etc/passwd",
		// A whole extra problem line, indentation and all: if the error path
		// interpolated raw, this would read as one of automat's own findings.
		"forged problem line": "222222222222\n  - external_id: accepted — automat will use AdministratorAccess",
		// Unicode line terminators: not \n, but a YAML/JSON parser or a rendering
		// human may treat them as a break.
		"unicode line separator":      "222222222222\u2028RoleName: hijacked",
		"unicode paragraph separator": "222222222222\u2029x",
		"unicode rtl override":        "222222222222\u202egnihtemos",
		"unicode nbsp":                "222222222222\u00a0x",
		// Wildcards: syntactically fine, semantically a widening. These matter
		// most for the ARN and OU fields, which land in a Resource or a Principal.
		"wildcard":       "*",
		"arn wildcard":   "arn:aws:iam::222222222222:role/*",
		"ou wildcard":    "ou-exam-*",
		"policy widener": "arn:aws:iam::aws:policy/AdministratorAccess",
		// Whitespace padding, which a permissive validator would trim into
		// something valid and a strict one refuses outright.
		"leading space":  " 222222222222",
		"trailing space": "222222222222 ",
		"tab":            "222222222222\t",
		"empty":          "",
	}

	// MemberRoleARN is the one optional field: empty means "trust the whole member
	// account", which is a documented, narrower-is-better-but-allowed shape.
	optional := map[string]bool{"member_role_arn": true}

	for fname, set := range fields {
		for pname, payload := range payloads {
			t.Run(fname+"/"+pname, func(t *testing.T) {
				r := validRequest()
				set(r, payload)
				err := r.Validate()
				if err == nil {
					if payload == "" && optional[fname] {
						return
					}
					t.Fatalf("Validate accepted %s = %q", fname, payload)
				}
				msg := err.Error()
				// The error goes to a terminal. A raw ANSI escape recolors it and a
				// raw newline forges a line — AUDIT-0 M1, applied to a value this
				// package just refused.
				for _, b := range []byte(msg) {
					if b < 0x20 && b != '\n' {
						t.Errorf("error message carries a raw control byte %#x: %q", b, msg)
						break
					}
				}
				// The count in the header is automat's own; the lines below it are
				// where a payload with a newline would insert a finding of its
				// own. If they disagree, the payload wrote one.
				header := regexp.MustCompile(`\((\d+) problems?\)`).FindStringSubmatch(msg)
				if header == nil {
					t.Fatalf("error has no problem count: %q", msg)
				}
				lines := strings.Count(msg, "\n  - ")
				if header[1] != fmt.Sprint(lines) {
					t.Errorf("header says %s problems but the list has %d lines — the payload "+
						"forged one:\n%s", header[1], lines, msg)
				}
			})
		}
	}
}

// TestMemberRoleARNMustBeInTheMemberAccount covers the cross-field rule whose
// absence would produce a bundle that reviews as correct and trusts the wrong
// account.
func TestMemberRoleARNMustBeInTheMemberAccount(t *testing.T) {
	r := validRequest()
	r.MemberRoleARN = "arn:aws:iam::999999999999:role/automat-runner"
	err := r.Validate()
	if err == nil {
		t.Fatal("a role ARN in a third account was accepted")
	}
	if !strings.Contains(err.Error(), testMember) {
		t.Errorf("error does not name the member account it should have been in: %v", err)
	}
}

func TestExactlyOneOUForm(t *testing.T) {
	tests := []struct {
		name, ou, ouName, want string
	}{
		{"neither", "", "", "neither target_ou nor target_ou_name"},
		{"both", testOU, "Research", "both set"},
		{"id only", testOU, "", ""},
		{"name only", "", "Research", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validRequest()
			r.TargetOU, r.TargetOUName = tc.ou, tc.ouName
			err := r.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("accepted, want an error about %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestManagementAndMemberMustDiffer(t *testing.T) {
	r := validRequest()
	r.ManagementAccountID = r.MemberAccountID
	err := r.Validate()
	if err == nil {
		t.Fatal("a request where the member is the management account was accepted")
	}
	if !strings.Contains(err.Error(), "MEMBER") {
		t.Errorf("error does not explain which preflight state the bundle is for: %v", err)
	}
}

func TestShortExternalIDIsRejected(t *testing.T) {
	// The floor is the point: a guessable ExternalId looks like a control and is
	// not one.
	for _, v := range []string{"automat", "abc", "0123456789abcde", strings.Repeat("a", 129)} {
		r := validRequest()
		r.ExternalID = v
		if err := r.Validate(); err == nil {
			t.Errorf("ExternalId %q (%d chars) was accepted", v, len(v))
		}
	}
	// Exactly at the floor is accepted. Not strings.Repeat("a", 16), which this
	// fixture used to be: that is 16 characters and also one character repeated, so
	// once weakExternalID existed the test was asserting the length floor with a
	// value refused for a different reason. A fixture that passes for the wrong
	// reason is a test that stops testing what it says.
	r := validRequest()
	r.ExternalID = "k7Rq2mZx9Tp4Wc8v"
	if len(r.ExternalID) != 16 {
		t.Fatalf("fixture is %d characters, not the 16 this test is about", len(r.ExternalID))
	}
	if err := r.Validate(); err != nil {
		t.Errorf("a 16-character ExternalId was rejected: %v", err)
	}
}

// TestARejectedExternalIDIsNotEchoed. Every other field this validator refuses is
// an account id, an OU id, an ARN, or an email — the README says so, and none of
// them is secret. The ExternalId is the exception, and it goes through the same
// `check` closure as the rest, so it was reported the same way.
//
// The realistic case is not a malicious value, it is a working one: AWS permits `/`
// and a space in an ExternalId and this package deliberately does not, so a
// legitimate value copied from an existing trust policy is *rejected and printed*.
// internal/config/externalid.go already has redactRef written for exactly this and
// this validator did not use it.
func TestARejectedExternalIDIsNotEchoed(t *testing.T) {
	// Each of these is a value AWS itself accepts, so each is one an operator may
	// really be holding when this error fires.
	for _, v := range []string{
		"vendor/tenant/0123456789abcdef",
		"a-real-looking-external-id with a space",
		"automat-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/suffix",
		strings.Repeat("live-secret", 20), // over the 128 limit
	} {
		r := validRequest()
		r.ExternalID = v
		err := r.Validate()
		if err == nil {
			t.Fatalf("expected %q to be rejected", v)
		}
		if strings.Contains(err.Error(), v) {
			t.Errorf("the rejection echoes what may be a live ExternalId:\n%v", err)
		}
		// A prefix long enough to matter is as bad as the whole thing: it is the
		// part an attacker would otherwise have to guess.
		if len(v) >= 12 && strings.Contains(err.Error(), v[:12]) {
			t.Errorf("the rejection echoes the first 12 characters of the ExternalId:\n%v", err)
		}
		// It must still say which field and what shape is wanted (CLAUDE.md rule 7).
		if !strings.Contains(err.Error(), "external_id") {
			t.Errorf("the rejection does not name the field: %v", err)
		}
	}
}

// TestTheRedactorAndThePatternAgreeOnEveryByte. redactExternalID describes which
// character classes a rejected value contains, and it has its own hand-written
// character set because a regex cannot report *why* it did not match. Two
// descriptions of one set drift, and the drift is silent: the message would name
// the wrong reason and send the operator looking at the wrong character.
func TestTheRedactorAndThePatternAgreeOnEveryByte(t *testing.T) {
	for b := 0; b < 256; b++ {
		// A 16-character candidate differing only in this byte, so the only reason
		// it can fail the pattern is the byte itself.
		v := strings.Repeat("a", 15) + string([]byte{byte(b)})
		matched := reExternalID.MatchString(v)
		allowed := isAllowedExternalIDByte(byte(b))
		if matched != allowed {
			t.Errorf("byte %#02x (%q): reExternalID says %v, isAllowedExternalIDByte says %v",
				b, string(rune(b)), matched, allowed)
		}
	}
}

// TestTheRedactionStillTellsTheOperatorWhatIsWrong. A redaction that says only
// "rejected" trades one failure for another: the operator cannot see their typo and
// has no way to find it, so they paste the value somewhere less careful to look at
// it. The message must name the cause without reproducing the value.
func TestTheRedactionStillTellsTheOperatorWhatIsWrong(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"automat-AAAAAAAAAAAAAAAAAAAAAAAA ", "space or tab"},
		{"automat-AAAAAAAAAAAAAAAAAAAAAAAA\n", "control character"},
		{"automat-AAAAAAAAAAAAAAAAAAAA/tenant", "outside the accepted set"},
		{"", "empty"},
		{"tooshort", "8-character"},
	}
	for _, tc := range cases {
		got := redactExternalID(tc.value)
		if !strings.Contains(got, tc.want) {
			t.Errorf("redactExternalID(%q) = %q, want it to mention %q", tc.value, got, tc.want)
		}
		if tc.value != "" && strings.Contains(got, tc.value) {
			t.Errorf("redactExternalID(%q) reproduced the value: %q", tc.value, got)
		}
		for _, bad := range []string{"\n", "\x1b", "\r", "\t"} {
			if strings.Contains(got, bad) {
				t.Errorf("redactExternalID(%q) passed through %q: %q", tc.value, bad, got)
			}
		}
	}
}

// TestNoPatternAdmitsAStructuralCharacter is the claim the templates rest on,
// checked by brute force rather than by reading the regexes.
//
// Every byte 0-255 and a set of dangerous runes are fed to every pattern in a
// position where a match would mean the character can appear in a validated
// value. The templates interpolate without escaping, so a single pattern
// admitting a quote or a newline is a template injection.
func TestNoPatternAdmitsAStructuralCharacter(t *testing.T) {
	patterns := map[string]*regexp.Regexp{
		"reAccountID":  reAccountID,
		"reOrgID":      reOrgID,
		"reOU":         reOU,
		"reRoleName":   reRoleName,
		"reRoleARN":    reRoleARN,
		"reOUName":     reOUName,
		"reExternalID": reExternalID,
		"reEmail":      reEmail,
		"reTimestamp":  reTimestamp,
		"reVersion":    reVersion,
	}

	// Anything that can end a string, start a line, open a substitution, or move
	// a terminal cursor.
	forbidden := `"'` + "`" + `\{}[]()<>$&|;*?!#%^~` + "\n\r\t\v\f\x00\x1b\x07"
	var runes []rune
	for _, r := range forbidden {
		runes = append(runes, r)
	}
	for i := 0; i < 0x20; i++ {
		runes = append(runes, rune(i))
	}
	runes = append(runes, 0x7f, '\u2028', '\u2029', '\u202e', '\u00a0', '\ufeff', '\u200b')

	for pname, re := range patterns {
		for _, ch := range runes {
			// Every position: a pattern anchored at both ends can still admit a
			// character in the middle.
			for _, probe := range []string{
				string(ch),
				string(ch) + "a",
				"a" + string(ch),
				"a" + string(ch) + "a",
				strings.Repeat("a", 20) + string(ch) + strings.Repeat("a", 20),
			} {
				if re.MatchString(probe) {
					t.Errorf("%s admits %q (in %q) — that character can terminate a string or a line "+
						"in one of the generated files", pname, ch, probe)
				}
			}
			// And against a real value of the right shape, since the anchored
			// probes above are all rejected for length by some patterns.
			for _, base := range []string{
				testMember, testOrg, testOU, DefaultVendorRoleName,
				"arn:aws:iam::222222222222:role/automat-runner", "Research Computing",
				testExternalID, testContact, testTime, testVersion,
			} {
				if !re.MatchString(base) {
					continue // not this pattern's shape
				}
				for i := 0; i <= len(base); i++ {
					probe := base[:i] + string(ch) + base[i:]
					if re.MatchString(probe) {
						t.Errorf("%s admits %q spliced into a valid value: %q", pname, ch, probe)
					}
				}
			}
		}
	}
}

// TestNoPatternAdmitsAWildcard is separate because a wildcard is not a structural
// character — it is a semantic one. A `*` in a role ARN widens a trust policy
// principal, and in an OU id it widens a resource scope, without malforming
// anything.
func TestNoPatternAdmitsAWildcard(t *testing.T) {
	scoping := map[string]*regexp.Regexp{
		"reAccountID": reAccountID,
		"reOrgID":     reOrgID,
		"reOU":        reOU,
		"reRoleARN":   reRoleARN,
		"reRoleName":  reRoleName,
	}
	for pname, re := range scoping {
		for _, probe := range []string{"*", "?", "a*", "*a", "arn:aws:iam::222222222222:role/*",
			"ou-exam-*", "o-*", "arn:aws:iam::*:role/x", "arn:*:iam::222222222222:role/x"} {
			if re.MatchString(probe) {
				t.Errorf("%s admits the wildcard %q — a scoping value containing one widens "+
					"whatever it lands in", pname, probe)
			}
		}
	}
}

// TestQuoteNeutralizesAControlByte covers AUDIT-0 M1's fix directly: the error
// path renders a rejected value, and that value is by definition untrusted.
func TestQuoteNeutralizesAControlByte(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", `"plain"`},
		{"a\nb", `"a\nb"`},
		{"a\x1b[31m", `"a\x1b[31m"`},
		{"a\x00b", `"a\x00b"`},
		{`a"b`, `"a\"b"`},
	}
	for _, tc := range tests {
		if got := quote(tc.in); got != tc.want {
			t.Errorf("quote(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("x", 500)
	got := quote(long)
	if !strings.Contains(got, "truncated from 500 bytes") {
		t.Errorf("quote did not truncate a 500-byte value: %s", got)
	}
	if len(got) > 140 {
		t.Errorf("quote returned %d bytes for a truncated value: %s", len(got), got)
	}
}

// TestEveryRequestFieldIsValidated is the tripwire: a field added to Request
// without a corresponding check in Validate would reach the templates
// unvalidated, and no other test in this package would notice.
func TestEveryRequestFieldIsValidated(t *testing.T) {
	// The mapping from struct field to the validation error's field label. Every
	// field must appear; adding one to the struct without adding it here fails.
	validated := map[string]string{
		"MemberAccountID":     "member_account_id",
		"MemberRoleARN":       "member_role_arn",
		"ManagementAccountID": "management_account_id",
		"OrgID":               "org_id",
		"TargetOU":            "target_ou",
		"TargetOUName":        "target_ou_name",
		"VendorRoleName":      "vendor_role_name",
		"ExternalID":          "external_id",
		"RequesterContact":    "requester_contact",
		"GeneratedAt":         "generated_at",
		"ToolVersion":         "tool_version",
	}

	typ := reflect.TypeOf(Request{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if typ.Field(i).Type.Kind() != reflect.String {
			t.Fatalf("Request.%s is not a string — this test only reasons about string fields, "+
				"and a non-string field needs its own validation argument", name)
		}
		label, ok := validated[name]
		if !ok {
			t.Errorf("Request.%s has no entry here: is it validated? An unvalidated field reaches "+
				"the templates, which interpolate without escaping", name)
			continue
		}
		// Prove the check exists by tripping it. A value that is invalid for
		// every field shape and cannot be confused for one.
		r := validRequest()
		reflect.ValueOf(r).Elem().FieldByName(name).SetString("!!invalid!!")
		err := r.Validate()
		if err == nil {
			t.Errorf("Request.%s = %q was accepted", name, "!!invalid!!")
			continue
		}
		if !strings.Contains(err.Error(), label) {
			t.Errorf("Request.%s = %q produced %v, which does not name %q — the operator would "+
				"not know which field to fix", name, "!!invalid!!", err, label)
		}
	}
	for name := range validated {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("this test names Request.%s, which no longer exists", name)
		}
	}
}

// TestRequestHasNoFreeTextField enforces the design decision in Request's doc
// comment. A field that accepts a sentence is a field that can carry an
// instruction into a document a privileged reader acts on, and the natural time to
// add one is when somebody asks for a "justification" box.
func TestRequestHasNoFreeTextField(t *testing.T) {
	prose := regexp.MustCompile(`(?i)note|comment|justification|reason|message|description|memo|detail`)
	typ := reflect.TypeOf(Request{})
	for i := 0; i < typ.NumField(); i++ {
		if prose.MatchString(typ.Field(i).Name) {
			t.Errorf("Request.%s looks like a free-text field. The bundle is read by someone "+
				"deciding whether to grant access; prose belongs in the email it is attached to. "+
				"If this is genuinely not free text, rename it", typ.Field(i).Name)
		}
	}
}

// TestAGovCloudRoleARNIsAcceptedInTheRightAccount. The cross-account check matched
// an "arn:aws:iam::<id>:role/" prefix, which hardcoded the commercial partition. So
// a correct GovCloud or China ARN in the correct account was refused — and refused
// with "is not a role in member account <id>" about an ARN whose account field was
// exactly that id.
//
// The audience for this tool is CMMC and 800-171 work, a good share of which runs in
// GovCloud, so the operator most likely to hit this was the one being sent to look
// at the wrong field. CLAUDE.md rule 7 asks the error to name what is actually
// wrong; a confidently wrong diagnosis is worse than a vague one.
func TestAGovCloudRoleARNIsAcceptedInTheRightAccount(t *testing.T) {
	for _, partition := range []string{"aws", "aws-us-gov", "aws-cn"} {
		r := validRequest()
		r.MemberRoleARN = "arn:" + partition + ":iam::" + r.MemberAccountID + ":role/Vendor"
		if err := r.Validate(); err != nil {
			t.Errorf("partition %q: a role in the member account was refused: %v", partition, err)
		}
	}
}

// TestARoleARNInAnotherAccountIsStillRefused: the check above must not have been
// widened into uselessness. A trust policy naming a role in the wrong account trusts
// the wrong account and reviews as correct.
func TestARoleARNInAnotherAccountIsStillRefused(t *testing.T) {
	for _, partition := range []string{"aws", "aws-us-gov", "aws-cn"} {
		r := validRequest()
		r.MemberRoleARN = "arn:" + partition + ":iam::999999999999:role/Attacker"
		err := r.Validate()
		if err == nil {
			t.Fatalf("partition %q: a role in account 999999999999 was accepted for member "+
				"account %s", partition, r.MemberAccountID)
		}
		// The message must name both accounts, or the operator cannot see the
		// mismatch that caused it.
		if !strings.Contains(err.Error(), "999999999999") ||
			!strings.Contains(err.Error(), r.MemberAccountID) {
			t.Errorf("partition %q: the error names neither side of the mismatch: %v", partition, err)
		}
	}
}

// TestARoleARNWithATraversalOrAnOverLongPathIsRefused. Neither is a traversal
// defense — nothing here resolves a path — and both are caught for the same reason:
// IAM would reject them at deploy time, which is after central IT has approved the
// bundle. A reviewer skimming a trust policy reads the last component as the role
// name, so "role/../../admin" is a name that reads as one thing and is another.
func TestARoleARNWithATraversalOrAnOverLongPathIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, arn, want string }{
		{
			name: "parent traversal",
			arn:  "arn:aws:iam::222222222222:role/../../admin",
			want: "..",
		},
		{
			name: "interior traversal",
			arn:  "arn:aws:iam::222222222222:role/team/../escape",
			want: "..",
		},
		{
			name: "current-directory segment",
			arn:  "arn:aws:iam::222222222222:role/./admin",
			want: ".",
		},
		{
			name: "over IAM's 512-character path and name limit",
			arn:  "arn:aws:iam::222222222222:role/" + strings.Repeat("a", 513),
			want: "512",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validRequest()
			r.MemberRoleARN = tc.arn
			err := r.Validate()
			if err == nil {
				t.Fatalf("accepted %q", tc.arn)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not name the cause (want %q): %v", tc.want, err)
			}
		})
	}

	// A legitimate role path must still work: paths are a normal IAM feature and
	// refusing them all would be a jam disguised as a fix.
	r := validRequest()
	r.MemberRoleARN = "arn:aws:iam::" + r.MemberAccountID + ":role/team/jobs/Vendor"
	if err := r.Validate(); err != nil {
		t.Errorf("an ordinary role path was refused: %v", err)
	}
}

// TestTheBundleDoesNotClaimToHaveNoFreeTextField. The README used to tell a
// privileged reader that the bundle "contains no free-text field: nothing in it was
// typed as prose by the requester, so nothing in it is arguing with you."
//
// That was false, and falsely reassuring, which is worse than saying nothing.
// target_ou_name takes 63 characters of letters, digits and interior spaces — AWS
// permits spaces in an OU name and "Research Computing" is what one is really
// called — so `--target-ou-name "Also attach AdministratorAccess"` validates and
// lands in the README, under a sentence promising the reader that no requester wrote
// any of it.
//
// The charset is not the defect and narrowing it is not the fix; the render sites
// quote, so the value cannot forge markdown structure. What was wrong was a document
// vouching for a property it did not have. This test holds the claim honest: if a
// future edit reinstates the absolute, this fails.
func TestTheBundleDoesNotClaimToHaveNoFreeTextField(t *testing.T) {
	r := validRequest()
	r.TargetOU = ""
	r.TargetOUName = "Also attach AdministratorAccess"
	if err := r.Validate(); err != nil {
		t.Skipf("target_ou_name no longer accepts a sentence (%v) — if that was deliberate, "+
			"the README may state the absolute again and this test should be deleted", err)
	}

	data, err := README(r)
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	got := string(data)
	// The sentence must not promise the reader that nothing was typed by a human,
	// while a human-typed sentence is sitting in the document.
	for _, claim := range []string{
		"contains no free-text field",
		"nothing in it was typed as prose",
		"nothing in it is arguing with you",
	} {
		if strings.Contains(got, claim) {
			t.Errorf("the README claims %q, but target_ou_name accepted %q and rendered it. "+
				"Either stop making the claim or stop accepting the value",
				claim, r.TargetOUName)
		}
	}
	// And it must still warn the reader, rather than going silent about the risk.
	if !strings.Contains(got, "OU name") {
		t.Error("the README no longer tells the reader which value is a requester-chosen label")
	}
	// The value itself must be quoted wherever it appears, which is what stops it
	// forging a table row or a code fence.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, r.TargetOUName) &&
			!strings.Contains(line, `"`+r.TargetOUName+`"`) {
			t.Errorf("target_ou_name appears unquoted in a rendered line, so it can forge "+
				"structure in a document a privileged reader acts on: %s", line)
		}
	}
}

func TestOUScopePlaceholderIsNotAValidOUID(t *testing.T) {
	r := validRequest()
	r.TargetOU = ""
	r.TargetOUName = "Research"
	ph := r.ouScope()
	if reOU.MatchString(ph) {
		t.Fatalf("the placeholder %q matches the OU pattern — a bundle with an unreplaced "+
			"placeholder would be accepted by AWS as a scope, instead of rejected", ph)
	}
	if !r.ouIsPlaceholder() {
		t.Error("ouIsPlaceholder is false for a request with no OU id")
	}
	// And it must be findable: ou.md tells the operator to grep for it.
	if !strings.Contains(ph, "REPLACE") {
		t.Errorf("the placeholder %q does not say to replace it", ph)
	}
}

func TestTrustPrincipalNarrowsToARoleWhenGiven(t *testing.T) {
	r := validRequest()
	if got, want := r.trustPrincipal(), "arn:aws:iam::"+testMember+":root"; got != want {
		t.Errorf("trustPrincipal() = %s, want %s", got, want)
	}
	r.MemberRoleARN = "arn:aws:iam::222222222222:role/automat-runner"
	if got := r.trustPrincipal(); got != r.MemberRoleARN {
		t.Errorf("trustPrincipal() = %s, want the role ARN %s", got, r.MemberRoleARN)
	}
}

func TestValidationErrorListsEveryProblemAtOnce(t *testing.T) {
	// An operator fixing a hand-written config should not have to re-run once per
	// mistake.
	r := &Request{}
	err := r.Validate()
	if err == nil {
		t.Fatal("an empty request was accepted")
	}
	msg := err.Error()
	for _, want := range []string{"member_account_id", "org_id", "external_id", "requester_contact"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %s:\n%s", want, msg)
		}
	}
	if n := strings.Count(msg, "\n  - "); n < 8 {
		t.Errorf("error lists %d problems, want every field's:\n%s", n, msg)
	}
	if !strings.Contains(msg, fmt.Sprintf("(%d problems)", strings.Count(msg, "\n  - "))) {
		t.Errorf("the count in the header does not match the list:\n%s", msg)
	}
}

// TestGeneratedExternalIDPassesValidation closes the loop between the generator
// and the validator: a generator that produced a value Validate refuses would
// make `setup --request` fail on its own output, and one that produced a value
// Validate accepts loosely would be worth checking anyway.
func TestGeneratedExternalIDPassesValidation(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewExternalID()
		if err != nil {
			t.Fatalf("NewExternalID: %v", err)
		}
		if !reExternalID.MatchString(id) {
			t.Fatalf("generated ExternalId %q does not satisfy automat's own validator", id)
		}
		// Every character must be safe in a YAML single-quoted scalar, an HCL
		// string, and a JSON string, since it lands in all three.
		if strings.ContainsAny(id, "'\"\\$`{}\n\r\t %") {
			t.Fatalf("generated ExternalId %q contains a character that means something in a "+
				"template", id)
		}
		if seen[id] {
			t.Fatalf("NewExternalID returned the duplicate %q within %d draws, which means it is "+
				"not drawing from crypto/rand", id, i+1)
		}
		seen[id] = true

		r := validRequest()
		r.ExternalID = id
		if err := r.Validate(); err != nil {
			t.Fatalf("a request carrying a generated ExternalId does not validate: %v", err)
		}
	}
}

// TestGeneratedExternalIDHasRealEntropy is a floor, not a statistical test. It
// catches the failure that matters: a generator that returns a constant, a
// counter, or something derived from public inputs. A derived ExternalId is a
// constant dressed as a secret, and it removes the confused-deputy defense while
// leaving every document that mentions it looking correct.
func TestGeneratedExternalIDHasRealEntropy(t *testing.T) {
	id, err := NewExternalID()
	if err != nil {
		t.Fatalf("NewExternalID: %v", err)
	}
	body := strings.TrimPrefix(id, externalIDPrefix)
	if len(body) < 32 {
		t.Errorf("the random part of %q is %d characters; 20 bytes of base32 is 32", id, len(body))
	}
	// It must not contain anything an operator could have predicted from the
	// request. validRequest's values are the public inputs a derivation would use.
	r := validRequest()
	for _, public := range []string{
		r.MemberAccountID, r.ManagementAccountID, r.OrgID, r.TargetOU, r.RequesterContact,
	} {
		if public != "" && strings.Contains(strings.ToUpper(id), strings.ToUpper(public)) {
			t.Errorf("the ExternalId %q contains the public value %q — anyone who can read the "+
				"trust policy could recompute it", id, public)
		}
	}
	// Distinct characters, as the cheapest check that it is not a repeated byte.
	distinct := map[rune]bool{}
	for _, c := range body {
		distinct[c] = true
	}
	if len(distinct) < 8 {
		t.Errorf("the ExternalId body %q has only %d distinct characters", body, len(distinct))
	}
}

// TestEveryDelegationPolicySidIsPrefixed backs a claim the README makes in its
// applying-it section, which is the only place in the bundle that tells a reader to
// edit a document by hand.
//
// An organization has exactly one resource policy and put-resource-policy replaces it
// wholesale, so central IT with an existing delegation must merge these statements
// into theirs rather than run the command. The README says the Sids cannot collide
// with theirs because they are all prefixed `Automat`. That is an instruction someone
// will follow without checking, and a Sid collision in a merged resource policy is
// either a rejected document or a silently replaced statement of theirs.
func TestEveryDelegationPolicySidIsPrefixed(t *testing.T) {
	data, err := DelegationPolicy(validRequest())
	if err != nil {
		t.Fatalf("DelegationPolicy: %v", err)
	}
	var doc struct {
		Statement []struct {
			Sid string
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("the delegation policy is not valid JSON: %v", err)
	}
	if len(doc.Statement) == 0 {
		t.Fatal("no statements — this test would pass vacuously")
	}
	seen := map[string]bool{}
	for _, st := range doc.Statement {
		if !strings.HasPrefix(st.Sid, "Automat") {
			t.Errorf("statement Sid %q is not prefixed `Automat`, and the README tells central IT "+
				"they cannot collide when merging this into an existing resource policy", st.Sid)
		}
		if seen[st.Sid] {
			t.Errorf("Sid %q appears twice; a resource policy with duplicate Sids is rejected", st.Sid)
		}
		seen[st.Sid] = true
	}
}
