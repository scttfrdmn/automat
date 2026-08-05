// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestNoTemplateSeesAnUnvalidatedValue is the assertion doc.go names.
//
// Every renderer must call Validate before writing a byte. The test proves it the
// only way that cannot be faked: it hands each renderer a Request that is invalid
// in one field and requires both an error and no output. A renderer that
// interpolated first and validated later — or that validated a copy — would return
// bytes here.
func TestNoTemplateSeesAnUnvalidatedValue(t *testing.T) {
	for _, rd := range renderers {
		for _, name := range []string{
			"MemberAccountID", "ManagementAccountID", "OrgID", "TargetOU",
			"VendorRoleName", "ExternalID", "RequesterContact", "GeneratedAt",
			"ToolVersion", "MemberRoleARN",
		} {
			t.Run(rd.name+"/"+name, func(t *testing.T) {
				r := validRequest()
				payload := "x'\n      ManagedPolicyArns: [arn:aws:iam::aws:policy/AdministratorAccess]\n      y: '"
				reflect.ValueOf(r).Elem().FieldByName(name).SetString(payload)
				got, err := rd.render(r)
				if err == nil {
					t.Fatalf("%s rendered %d bytes from an invalid %s", rd.name, len(got), name)
				}
				if got != nil {
					t.Errorf("%s returned %d bytes alongside an error — a caller that ignores the "+
						"error would write a forged file", rd.name, len(got))
				}
			})
		}
	}
}

// TestEveryRendererIsReachable guards the renderers table against a file that
// exists as a function but is never written, and against a name typo that would
// produce a bundle missing a file central IT needs.
func TestEveryRendererIsReachable(t *testing.T) {
	want := []string{FileREADME, FilePolicy, FileOU, FileRoleCFN, FileRoleTF}
	sort.Strings(want)
	if got := FileNames(); !reflect.DeepEqual(got, want) {
		t.Errorf("FileNames() = %v, want %v", got, want)
	}
	if len(renderers) != renderersCount {
		t.Errorf("%d renderers, but renderersCount is %d", len(renderers), renderersCount)
	}
	seen := map[string]bool{}
	for _, rd := range renderers {
		if seen[rd.name] {
			t.Errorf("two renderers write %s — one would silently overwrite the other", rd.name)
		}
		seen[rd.name] = true
		if rd.render == nil {
			t.Errorf("%s has no renderer", rd.name)
		}
	}
}

// decodePolicy parses the rendered delegation policy back into a shape a test can
// assert on. Parsing rather than string-matching is the point: a claim about what
// the policy grants must be checked against the policy's structure.
type parsedStatement struct {
	Sid       string
	Effect    string
	Principal struct{ AWS string }
	Action    []string
	Resource  []string
	Condition map[string]map[string]string
}

func decodePolicy(t *testing.T, r *Request) []parsedStatement {
	t.Helper()
	data, err := DelegationPolicy(r)
	if err != nil {
		t.Fatalf("DelegationPolicy: %v", err)
	}
	var doc struct {
		Version   string
		Statement []parsedStatement
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("the rendered policy is not valid JSON: %v\n%s", err, data)
	}
	if doc.Version != "2012-10-17" {
		t.Errorf("policy Version = %q", doc.Version)
	}
	return doc.Statement
}

// TestDelegationPolicyGrantsNothingUnconditional walks the rendered policy and
// checks the three scoping mechanisms DESIGN §5 requires. The third — the tag
// condition on modification — is the one a reviewer misses, so it is checked
// per-statement rather than by presence anywhere in the file.
func TestDelegationPolicyGrantsNothingUnconditional(t *testing.T) {
	r := validRequest()
	stmts := decodePolicy(t, r)
	// Create, modify, tag, attach, read. Tagging is its own statement because it
	// needs a different condition from creation — see escalation_test.go.
	if len(stmts) != 5 {
		t.Fatalf("%d statements, want 5", len(stmts))
	}

	byID := map[string]parsedStatement{}
	for _, s := range stmts {
		byID[s.Sid] = s
		if s.Effect != "Allow" {
			t.Errorf("%s: Effect = %q", s.Sid, s.Effect)
		}
		if s.Principal.AWS != r.trustPrincipal() {
			t.Errorf("%s: Principal = %q, want the member account or its role %q",
				s.Sid, s.Principal.AWS, r.trustPrincipal())
		}
		for _, res := range s.Resource {
			if res == "*" {
				t.Errorf("%s: Resource is *, which scopes to the whole organization", s.Sid)
			}
			// Every resource must name this organization. One that does not is
			// either a bug or a widening.
			if !strings.Contains(res, r.OrgID) {
				t.Errorf("%s: resource %q does not name organization %s", s.Sid, res, r.OrgID)
			}
			if !strings.Contains(res, r.ManagementAccountID) {
				t.Errorf("%s: resource %q does not name the management account", s.Sid, res)
			}
		}
		for _, a := range s.Action {
			if strings.Contains(a, "*") {
				t.Errorf("%s: action %q contains a wildcard", s.Sid, a)
			}
			if !strings.HasPrefix(a, "organizations:") {
				t.Errorf("%s: action %q is not an Organizations action — the delegation policy "+
					"grants nothing else", s.Sid, a)
			}
		}
	}

	// Creation is gated on the request tag, because there is no resource yet to
	// carry one.
	create, ok := byID["AutomatCreatePoliciesMarkedAsItsOwn"]
	if !ok {
		t.Fatal("no create statement")
	}
	if got := create.Condition["StringEquals"]["aws:RequestTag/automat:managed-by"]; got != "automat" {
		t.Errorf("create statement is not gated on the request tag (got %q) — automat could then "+
			"create an untagged policy, which nothing downstream would recognize as its own", got)
	}

	// Modification is gated on the resource tag. Without this, "manage SCPs on
	// this OU" includes central IT's own SCP attached there.
	modify, ok := byID["AutomatModifyOnlyPoliciesItCreated"]
	if !ok {
		t.Fatal("no modify statement")
	}
	if got := modify.Condition["StringEquals"]["aws:ResourceTag/automat:managed-by"]; got != "automat" {
		t.Errorf("modify statement is not gated on the resource tag (got %q) — the delegate could "+
			"update or delete a policy central IT wrote", got)
	}
	for _, a := range modify.Action {
		if a == "organizations:CreatePolicy" {
			t.Error("CreatePolicy is in the resource-tag-gated statement, where the condition can " +
				"never be satisfied: a policy that does not exist yet carries no tag")
		}
	}

	// Attachment is gated both ways: the policy must be automat's and the target
	// must be in the subtree.
	attach, ok := byID["AutomatAttachItsPoliciesWithinTheDelegatedSubtree"]
	if !ok {
		t.Fatal("no attach statement")
	}
	if got := attach.Condition["StringEquals"]["aws:ResourceTag/automat:managed-by"]; got != "automat" {
		t.Errorf("attach statement is not gated on the resource tag (got %q) — the delegate could "+
			"detach central IT's SCP from the OU", got)
	}
	foundOU := false
	for _, res := range attach.Resource {
		if strings.Contains(res, ":ou/") && strings.HasSuffix(res, r.TargetOU) {
			foundOU = true
		}
	}
	if !foundOU {
		t.Errorf("attach statement does not name OU %s as a target: %v", r.TargetOU, attach.Resource)
	}

	// Reads carry no condition, and must be reads.
	read, ok := byID["AutomatReadTheOrganizationItOperatesIn"]
	if !ok {
		t.Fatal("no read statement")
	}
	for _, a := range read.Action {
		verb := strings.TrimPrefix(a, "organizations:")
		if !strings.HasPrefix(verb, "Describe") && !strings.HasPrefix(verb, "List") {
			t.Errorf("read statement contains %q, which is not a Describe or a List", a)
		}
	}
}

// TestDelegationPolicyGrantsNoAccountLifecycle is the negative half: the actions
// the README promises are absent must actually be absent. A doc claim is false
// until traced to code.
func TestDelegationPolicyGrantsNoAccountLifecycle(t *testing.T) {
	forbidden := []string{
		"organizations:CloseAccount",
		"organizations:RemoveAccountFromOrganization",
		"organizations:DeleteOrganization",
		"organizations:DeleteOrganizationalUnit",
		"organizations:LeaveOrganization",
		"organizations:EnableAWSServiceAccess",
		"organizations:DisableAWSServiceAccess",
		"organizations:EnablePolicyType",
		"organizations:DisablePolicyType",
		"organizations:RegisterDelegatedAdministrator",
		"organizations:PutResourcePolicy",
		"organizations:DeleteResourcePolicy",
		"organizations:InviteAccountToOrganization",
		"organizations:AcceptHandshake",
		"organizations:CreateAccount",
		"organizations:MoveAccount",
		"organizations:CreateOrganizationalUnit",
		"organizations:UpdateOrganizationalUnit",
		"iam:",
		"sts:",
	}
	all := append(append(append([]string{}, scpCreateActions...), scpModifyActions...), scpAttachActions...)
	all = append(all, readActions...)
	for _, f := range forbidden {
		for _, a := range all {
			if strings.HasPrefix(a, f) || a == f {
				t.Errorf("the delegation policy grants %q, which the README says it does not. "+
					"Either the grant is wrong or the README is lying to a reviewer", a)
			}
		}
	}
	// PutResourcePolicy in particular: the delegate could rewrite the very policy
	// that bounds it.
	if strings.Contains(strings.Join(all, " "), "ResourcePolicy") {
		t.Error("the delegation policy touches the organization's resource policy — the delegate " +
			"could rewrite its own grant")
	}
}

// TestVendorRoleGrantsNoPolicyActions is DESIGN §5's split, checked in both
// templates. If the role could manage policies, the two-halves argument in the
// README stops being true and the bundle stops being reviewable in two pieces.
func TestVendorRoleGrantsNoPolicyActions(t *testing.T) {
	r := validRequest()
	cfn, err := VendorRoleCFN(r)
	if err != nil {
		t.Fatalf("VendorRoleCFN: %v", err)
	}
	tf, err := VendorRoleTF(r)
	if err != nil {
		t.Fatalf("VendorRoleTF: %v", err)
	}
	policyish := regexp.MustCompile(`organizations:\w*Policy\w*`)
	for name, data := range map[string][]byte{FileRoleCFN: cfn, FileRoleTF: tf} {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue // the comment that says so
			}
			if m := policyish.FindString(line); m != "" {
				t.Errorf("%s grants %s: %s", name, m, strings.TrimSpace(line))
			}
		}
		for _, a := range []string{"organizations:CloseAccount", "organizations:RemoveAccountFrom",
			"organizations:DeleteOrganization", "AdministratorAccess", "ManagedPolicyArns"} {
			if strings.Contains(string(data), a) {
				t.Errorf("%s contains %q", name, a)
			}
		}
		// An IAM *action* — `iam:` in an ARN is expected (the trust principal is
		// one), but the role must grant nothing in IAM: a role that can attach a
		// managed policy can grant itself anything.
		if m := regexp.MustCompile(`(?:^|[^:\w])iam:[A-Z]\w+`).FindString(string(data)); m != "" {
			t.Errorf("%s grants an IAM action (%s) — the vendor role touches Organizations only",
				name, strings.TrimSpace(m))
		}
	}
}

// roleActions extracts the Organizations actions a template grants, by statement,
// so the two templates can be compared as grants rather than as text.
func roleActions(t *testing.T, data string) map[string][]string {
	t.Helper()
	action := regexp.MustCompile(`organizations:[A-Za-z]+`)
	sid := regexp.MustCompile(`Sid\s*[:=]\s*"?([A-Za-z]+)"?`)
	out := map[string][]string{}
	cur := ""
	for _, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := sid.FindStringSubmatch(trimmed); m != nil {
			cur = m[1]
			continue
		}
		if cur == "" {
			continue
		}
		out[cur] = append(out[cur], action.FindAllString(trimmed, -1)...)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// TestCFNAndTFGrantTheSameThing is the drift detector role.go names. Two files
// that drift apart mean central IT approved one thing and deployed another, and
// nothing else in the repo would notice: they are separate literal templates.
func TestCFNAndTFGrantTheSameThing(t *testing.T) {
	r := validRequest()
	cfn, err := VendorRoleCFN(r)
	if err != nil {
		t.Fatalf("VendorRoleCFN: %v", err)
	}
	tf, err := VendorRoleTF(r)
	if err != nil {
		t.Fatalf("VendorRoleTF: %v", err)
	}

	gotCFN, gotTF := roleActions(t, string(cfn)), roleActions(t, string(tf))
	if !reflect.DeepEqual(gotCFN, gotTF) {
		t.Errorf("the two templates grant different things.\ncfn: %v\ntf:  %v", gotCFN, gotTF)
	}
	// And both must cover the documented action list exactly — a template that
	// dropped an action would fail the vend at runtime, and one that gained an
	// action would grant something vendorRoleActions does not explain.
	var want []string
	for _, a := range vendorRoleActions {
		want = append(want, a.action)
	}
	sort.Strings(want)
	// Compared as sets, not multisets: one action may legitimately appear in more
	// than one statement, because that is how an action gets two different
	// conditions. organizations:TagResource is granted twice for exactly that
	// reason — once for accounts, gated on automat:vended-by, and once for OUs in
	// the subtree, which cannot carry that gate because a fresh OU has no tags. A
	// count-sensitive comparison here would report that split as drift and push
	// toward merging the statements back into one broader grant.
	for name, got := range map[string]map[string][]string{FileRoleCFN: gotCFN, FileRoleTF: gotTF} {
		seen := map[string]bool{}
		for _, as := range got {
			for _, a := range as {
				seen[a] = true
			}
		}
		var flat []string
		for a := range seen {
			flat = append(flat, a)
		}
		sort.Strings(flat)
		if !reflect.DeepEqual(flat, want) {
			t.Errorf("%s grants %v, want exactly %v", name, flat, want)
		}
	}

	// The conditions must match too: an action granted with a tag condition in one
	// file and without it in the other is the same drift, one step subtler.
	for _, cond := range []string{
		"aws:RequestTag/automat:vended-by",
		"aws:RequestTag/automat:ou",
		"sts:ExternalId",
	} {
		if !strings.Contains(string(cfn), cond) {
			t.Errorf("%s is missing the condition %s", FileRoleCFN, cond)
		}
		if !strings.Contains(string(tf), cond) {
			t.Errorf("%s is missing the condition %s", FileRoleTF, cond)
		}
	}
	// Both must scope MoveAccount and CreateOrganizationalUnit to the OU rather
	// than to *. The CFN says so with a literal ARN and the TF through a local,
	// so this checks each in its own idiom.
	if strings.Count(string(cfn), r.TargetOU) < 3 {
		t.Errorf("%s names OU %s fewer than 3 times — the scoped resources may be missing",
			FileRoleCFN, r.TargetOU)
	}
	if !strings.Contains(string(tf), "local.automat_target_ou") {
		t.Errorf("%s does not scope by OU", FileRoleTF)
	}
}

// TestTemplatesCarryNoGoFormatVerb catches the class of bug where a literal `%s`
// meant for Terraform's format() is written through a printf path, or a printf
// call loses its argument. Either produces a template with `%!s(MISSING)` or a
// stray verb in it, which deploys as garbage.
func TestTemplatesCarryNoGoFormatVerb(t *testing.T) {
	r := validRequest()
	for _, rd := range renderers {
		data, err := rd.render(r)
		if err != nil {
			t.Fatalf("%s: %v", rd.name, err)
		}
		s := string(data)
		for _, bad := range []string{"%!", "MISSING", "%%", "(BADINDEX)", "EXTRA string="} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q — a printf call in the renderer is malformed", rd.name, bad)
			}
		}
		// The one place a literal verb is legitimate is Terraform's own format().
		if rd.name == FileRoleTF {
			if !strings.Contains(s, `format(`) {
				t.Errorf("%s no longer calls format() — the check below is stale", rd.name)
			}
			continue
		}
		if regexp.MustCompile(`%[sdqvx]`).MatchString(s) {
			t.Errorf("%s contains an unsubstituted format verb:\n%s", rd.name,
				regexp.MustCompile(`.*%[sdqvx].*`).FindString(s))
		}
	}
}

// TestRenderedFilesAreValidForTheirFormat is a shape check, not a parser: the repo
// takes no YAML or HCL dependency (CLAUDE.md keeps the tree small), so the
// properties checked are the ones a broken interpolation would violate.
func TestRenderedFilesAreValidForTheirFormat(t *testing.T) {
	r := validRequest()

	policy, err := DelegationPolicy(r)
	if err != nil {
		t.Fatalf("DelegationPolicy: %v", err)
	}
	var any map[string]any
	if jerr := json.Unmarshal(policy, &any); jerr != nil {
		t.Errorf("%s is not valid JSON: %v", FilePolicy, jerr)
	}
	// SetEscapeHTML(false) is deliberate; verify no < slipped in.
	if strings.Contains(string(policy), `\u00`) {
		t.Errorf("%s contains an escaped character sequence a human would misread: %s",
			FilePolicy, FilePolicy)
	}

	cfn, err := VendorRoleCFN(r)
	if err != nil {
		t.Fatalf("VendorRoleCFN: %v", err)
	}
	checkIndentation(t, FileRoleCFN, string(cfn))
	if !strings.HasPrefix(string(cfn), "AWSTemplateFormatVersion: '2010-09-09'\n") {
		t.Errorf("%s does not start with the template version line", FileRoleCFN)
	}
	for _, want := range []string{"Type: AWS::IAM::Role", "AssumeRolePolicyDocument:", "Outputs:"} {
		if !strings.Contains(string(cfn), want) {
			t.Errorf("%s is missing %q", FileRoleCFN, want)
		}
	}

	tf, err := VendorRoleTF(r)
	if err != nil {
		t.Fatalf("VendorRoleTF: %v", err)
	}
	if got := strings.Count(string(tf), "{") - strings.Count(string(tf), "}"); got != 0 {
		t.Errorf("%s has unbalanced braces (%+d)", FileRoleTF, got)
	}
	if got := strings.Count(string(tf), "["); got != strings.Count(string(tf), "]") {
		t.Errorf("%s has unbalanced brackets", FileRoleTF)
	}
	if n := strings.Count(string(tf), `"`) % 2; n != 0 {
		t.Errorf("%s has an odd number of double quotes — a string is unterminated", FileRoleTF)
	}

	for _, rd := range renderers {
		data, err := rd.render(r)
		if err != nil {
			t.Fatalf("%s: %v", rd.name, err)
		}
		if !strings.HasSuffix(string(data), "\n") {
			t.Errorf("%s does not end with a newline", rd.name)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.ContainsAny(line, "\r\x00\x1b\t") {
				t.Errorf("%s:%d contains a control character: %q", rd.name, i+1, line)
			}
			if strings.HasSuffix(line, " ") {
				t.Errorf("%s:%d has trailing whitespace: %q", rd.name, i+1, line)
			}
		}
	}
}

// checkIndentation verifies YAML indentation is a multiple of two with no tabs.
// A template whose indentation drifts by one space parses as a different
// document, or fails to parse, and the failure surfaces at deploy time in
// somebody else's account.
func checkIndentation(t *testing.T, name, data string) {
	t.Helper()
	for i, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent%2 != 0 {
			t.Errorf("%s:%d is indented %d spaces, which is not a multiple of two: %q",
				name, i+1, indent, line)
		}
	}
}

// TestREADMEMakesTheBlastRadiusArgument checks the content DESIGN §6 requires,
// since the README is the deliverable: a bundle whose cover note omits the
// argument is a bundle that does not get approved.
func TestREADMEMakesTheBlastRadiusArgument(t *testing.T) {
	r := validRequest()
	data, err := README(r)
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	s := string(data)
	for _, claim := range []string{
		// The three halves of the argument.
		"cannot place an account anywhere else",
		"cannot touch your policies",
		"cannot loosen anything you enforce",
		// The mechanism behind the third, stated so a reviewer can check it.
		"intersect",
		"institutional floor",
		// What it can do, stated plainly rather than buried.
		"What it *can* do",
		// The two files and which is which.
		FilePolicy,
		FileRoleCFN,
		FileRoleTF,
		// The reply path, and the ExternalId disclosure.
		testContact,
		"sts:ExternalId",
	} {
		if !strings.Contains(s, claim) {
			t.Errorf("README does not make the claim %q", claim)
		}
	}
	// It must not promise something the templates do not deliver.
	if strings.Contains(s, "read-only") {
		t.Error("README calls the grant read-only, which it is not")
	}
	if r.MemberRoleARN == "" && !strings.Contains(s, "Narrowing it further") {
		t.Error("README does not offer the narrower single-role form")
	}
}

// TestOUInstructionsAdaptToWhetherTheOUExists covers the branch that decides
// whether central IT has a step zero.
func TestOUInstructionsAdaptToWhetherTheOUExists(t *testing.T) {
	existing := validRequest()
	data, err := OUInstructions(existing)
	if err != nil {
		t.Fatalf("OUInstructions: %v", err)
	}
	if !strings.Contains(string(data), "Nothing to do here") {
		t.Error("ou.md asks for work when the OU already exists")
	}
	if strings.Contains(string(data), existing.ouScope()) != strings.Contains(string(data), testOU) {
		t.Error("ou.md's scope diagram does not name the real OU")
	}

	pending := validRequest()
	pending.TargetOU = ""
	pending.TargetOUName = "Research Computing"
	data, err = OUInstructions(pending)
	if err != nil {
		t.Fatalf("OUInstructions: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		"create-organizational-unit", pending.ouScope(), "grep",
		FilePolicy, FileRoleCFN, FileRoleTF,
		"Research Computing",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("ou.md does not mention %q", want)
		}
	}
	// The claim that a missed placeholder fails loudly is load-bearing: it is why
	// a half-substituted bundle is safe. It must be stated, and it must be true —
	// TestOUScopePlaceholderIsNotAValidOUID checks the truth.
	if !strings.Contains(s, "fails loudly") {
		t.Error("ou.md does not tell the operator that a missed placeholder fails loudly")
	}

	// And the README must add its step zero.
	readme, err := README(pending)
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	if !strings.Contains(string(readme), "Create the OU first") {
		t.Error("README does not tell central IT to create the OU before deploying")
	}
}

// TestNoProductOrVendorReference enforces CLAUDE.md rule 3 on the files that
// leave the building. These five are the most likely place for a comparison to
// slip in, because they are written to persuade.
func TestNoProductOrVendorReference(t *testing.T) {
	r := validRequest()
	// Vendor and product names that would violate rule 3, plus the phrasings that
	// smuggle one in without naming it.
	forbidden := []string{
		"control tower", "controltower", "landing zone", "account factory",
		"organizations formation", "terraform cloud", "hashicorp",
		"competitor", "unlike ", "instead of using", "vendor's",
	}
	for _, rd := range renderers {
		data, err := rd.render(r)
		if err != nil {
			t.Fatalf("%s: %v", rd.name, err)
		}
		lower := strings.ToLower(string(data))
		for _, f := range forbidden {
			if strings.Contains(lower, f) {
				t.Errorf("%s contains %q (CLAUDE.md rule 3)", rd.name, f)
			}
		}
	}
}

// TestRenderingIsDeterministic is what makes the golden files meaningful, and
// what makes a re-run report "unchanged" rather than "replaced": the renderers
// must be pure functions of the Request, with no clock and no map iteration order
// leaking into the output.
func TestRenderingIsDeterministic(t *testing.T) {
	r := validRequest()
	for _, rd := range renderers {
		first, err := rd.render(r)
		if err != nil {
			t.Fatalf("%s: %v", rd.name, err)
		}
		for i := 0; i < 20; i++ {
			again, err := rd.render(validRequest())
			if err != nil {
				t.Fatalf("%s: %v", rd.name, err)
			}
			if string(again) != string(first) {
				t.Fatalf("%s is not deterministic: run %d differs", rd.name, i+2)
			}
		}
	}
}

// TestNoRenderedFileLeaksTheExternalIDBeyondTheTrustPolicy bounds the disclosure
// the bundle makes. The ExternalId belongs in exactly one place in each role
// template — the trust policy condition — and nowhere in the policy or ou.md. A
// copy anywhere else widens the surface for no benefit.
func TestNoRenderedFileLeaksTheExternalIDBeyondTheTrustPolicy(t *testing.T) {
	r := validRequest()
	expected := map[string]int{
		FileRoleCFN: 1,
		FileRoleTF:  1,
		FilePolicy:  0,
		FileOU:      0,
		FileREADME:  0, // the README describes it; it does not repeat the value
	}
	for _, rd := range renderers {
		data, err := rd.render(r)
		if err != nil {
			t.Fatalf("%s: %v", rd.name, err)
		}
		if got := strings.Count(string(data), r.ExternalID); got != expected[rd.name] {
			t.Errorf("%s contains the ExternalId %d times, want %d", rd.name, got, expected[rd.name])
		}
	}
}
