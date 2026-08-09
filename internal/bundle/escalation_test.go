// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"regexp"
	"strings"
	"testing"
)

// The escalation tests. Each one encodes a specific multi-step attack on the
// delegation policy — the kind that gets past review because every individual
// statement reads as reasonable and only the composition is dangerous.
//
// They are separate from render_test.go's structural checks because these are not
// assertions about shape. Each is a claim the generated README.md makes to a CISO,
// stated as the attack that would falsify it. If one of these fails, the bundle is
// lying to the person who trusted it.

// statementText returns the text of one statement from a rendered role template,
// found by its Sid and ending where the next Sid begins. It works for both the CFN
// and Terraform renderings because both put the Sid on its own line and neither
// nests one statement inside another — which is exactly the shape
// TestRenderedFilesAreValidForTheirFormat holds them to.
func statementText(doc, sid string) (string, bool) {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		if !strings.Contains(line, "Sid") {
			continue
		}
		switch {
		case start < 0 && strings.Contains(line, sid):
			start = i
		case start >= 0:
			return strings.Join(lines[start:i], "\n"), true
		}
	}
	if start < 0 {
		return "", false
	}
	return strings.Join(lines[start:], "\n"), true
}

// TestDelegateCannotTagItsWayIntoCentralITsPolicies is the worst of the class.
//
// The attack, found by reading the rendered policy rather than the code:
//
//  1. Central IT has its own SCP, `institutional-baseline`, attached at or above
//     the delegated OU. It carries no automat tag, so the resource-tag conditions
//     are supposed to exclude it.
//  2. The delegate calls organizations:TagResource on that policy, applying
//     automat:managed-by=automat. A request-tag condition does not stop this: the
//     tag being applied IS automat's, which is exactly what the condition asks
//     for. The condition reads the tag the caller is writing.
//  3. Central IT's policy now carries the tag every other statement gates on.
//     UpdatePolicy, DeletePolicy, and DetachPolicy all become available against
//     it.
//
// The delegate can now rewrite or delete the institutional baseline. Every
// "cannot touch your policies" and "can never loosen your floor" sentence in the
// README is false, and the tag condition a reviewer was told to check is
// decorative: a principal that can write the tag a condition reads is not
// constrained by that condition.
func TestDelegateCannotTagItsWayIntoCentralITsPolicies(t *testing.T) {
	r := validRequest()
	stmts := decodePolicy(t, r)

	const ownerTag = "automat:managed-by"
	for _, s := range stmts {
		hasTagWrite := false
		for _, a := range s.Action {
			if a == "organizations:TagResource" || a == "organizations:UntagResource" {
				hasTagWrite = true
			}
		}
		if !hasTagWrite {
			continue
		}
		// A tag-writing statement must be gated on the resource ALREADY being
		// automat's. Gating only on the request tag authorizes tagging anything.
		if s.Condition["StringEquals"]["aws:ResourceTag/"+ownerTag] != "automat" {
			t.Errorf("%s grants a tag-writing action without requiring the target to already be "+
				"automat's (conditions: %v).\n"+
				"The delegate can then tag central IT's own SCP as automat:managed-by=automat and "+
				"inherit every resource-tag-gated grant over it — update, delete, detach. "+
				"A condition that reads a tag the caller writes constrains nothing.",
				s.Sid, s.Condition)
		}
		// And it must not be able to write outside automat's tag namespace: a
		// delegate that can set an arbitrary tag on an organization resource can
		// forge whatever other conditions central IT relies on elsewhere.
		keys, ok := s.Condition["ForAllValues:StringLike"]["aws:TagKeys"]
		if !ok || !strings.HasPrefix(keys, "automat:") {
			t.Errorf("%s grants a tag-writing action without restricting aws:TagKeys to automat's "+
				"namespace (conditions: %v) — the delegate could set any tag on any policy in the "+
				"organization, forging conditions central IT relies on elsewhere", s.Sid, s.Condition)
		}
	}
}

// TestDelegateCannotAttachPoliciesOutsideTheDelegatedOU covers the second half of
// the blast-radius claim, and a genuinely subtle AWS fact.
//
// An Organizations account ARN is arn:aws:organizations::<mgmt>:account/<org>/<id>
// — it encodes the ORGANIZATION, not the account's position in the OU tree. So a
// resource pattern of account/o-org/* does not mean "the accounts under the
// delegated OU". It means every account in the organization, including central
// IT's own.
//
// With AttachPolicy permitted against that pattern, the delegate can attach one of
// its own SCPs directly to any account in the organization. An SCP is a deny
// instrument evaluated by intersection (DESIGN §3 fact 7), so this is not a
// read-only mistake: attaching a restrictive SCP to central IT's production
// member account denies actions in it. The delegate cannot loosen anything, but it
// can lock somebody else's account down, and the README promises it "cannot place
// an account anywhere else" and cannot affect anything outside the OU.
//
// The narrow fix is the one DESIGN §5 and §8 already describe: automat attaches
// SCPs at the OU. Account-level attachment is not a capability it needs.
func TestDelegateCannotAttachPoliciesOutsideTheDelegatedOU(t *testing.T) {
	r := validRequest()
	stmts := decodePolicy(t, r)

	for _, s := range stmts {
		mutates := false
		for _, a := range s.Action {
			if a == "organizations:AttachPolicy" || a == "organizations:DetachPolicy" {
				mutates = true
			}
		}
		if !mutates {
			continue
		}
		for _, res := range s.Resource {
			// An account ARN as an attach target is org-wide by construction.
			if strings.Contains(res, ":account/") {
				t.Errorf("%s permits attaching to %q. An Organizations account ARN encodes the "+
					"organization, not the OU, so this pattern matches every account in the org — "+
					"including central IT's. The delegate could attach a denying SCP to somebody "+
					"else's account. automat attaches at the OU (DESIGN §5, §8); drop the account "+
					"target.", s.Sid, res)
			}
			// A root ARN would be worse: it is the whole organization.
			if strings.Contains(res, ":root/") {
				t.Errorf("%s permits attaching at %q — the organization root, which is above the "+
					"delegated OU and binds everything in the org", s.Sid, res)
			}
			// And an OU target must be the delegated one, not any OU.
			if strings.Contains(res, ":ou/") && !strings.Contains(res, r.TargetOU) {
				t.Errorf("%s permits attaching to %q, which is not the delegated OU %s",
					s.Sid, res, r.TargetOU)
			}
		}
	}
}

// TestNoMutatingStatementIsUnconditional is the general form of both findings
// above, so a future statement added without a condition fails here rather than
// waiting for the next audit.
func TestNoMutatingStatementIsUnconditional(t *testing.T) {
	r := validRequest()
	// Every action that changes something, and what each one must be gated on.
	// "resource" means the target must already be automat's; "request" means the
	// thing being created must mark itself as automat's.
	gate := map[string]string{
		"organizations:CreatePolicy":  "request",
		"organizations:UpdatePolicy":  "resource",
		"organizations:DeletePolicy":  "resource",
		"organizations:AttachPolicy":  "resource",
		"organizations:DetachPolicy":  "resource",
		"organizations:TagResource":   "resource",
		"organizations:UntagResource": "resource",
	}
	for _, s := range decodePolicy(t, r) {
		for _, a := range s.Action {
			want, mutating := gate[a]
			if !mutating {
				continue
			}
			var key string
			switch want {
			case "request":
				key = "aws:RequestTag/automat:managed-by"
			case "resource":
				key = "aws:ResourceTag/automat:managed-by"
			}
			if s.Condition["StringEquals"][key] != "automat" {
				t.Errorf("%s grants %s but is not gated on %s (conditions: %v)",
					s.Sid, a, key, s.Condition)
			}
		}
	}
}

// TestReadStatementIsScopedButHarmless records the deliberate asymmetry. The read
// statement spans the organization, because naming an OU means resolving its
// parents and `verify` reports on what it vended. That is visibility into the org
// structure, not change, and it is the one place the bundle asks for something
// wider than the OU — so it must contain nothing but reads, checked here rather
// than argued for in a comment.
func TestReadStatementIsScopedButHarmless(t *testing.T) {
	for _, s := range decodePolicy(t, validRequest()) {
		orgWide := false
		for _, res := range s.Resource {
			if strings.Contains(res, ":account/") || strings.Contains(res, ":root/") {
				orgWide = true
			}
		}
		if !orgWide {
			continue
		}
		for _, a := range s.Action {
			verb := strings.TrimPrefix(a, "organizations:")
			if !strings.HasPrefix(verb, "Describe") && !strings.HasPrefix(verb, "List") {
				t.Errorf("%s reaches organization-wide resources and grants %q, which is not a "+
					"read. Only visibility may be org-wide", s.Sid, a)
			}
		}
	}
}

// TestVendorRoleCannotMoveAnAccountOutOfTheSubtree is the vending half's version of
// the same question, and it turns on a fact worth stating in the test rather than
// in a comment: MoveAccount authorizes against the account being moved AND the
// destination parent. The account ARN pattern is necessarily org-wide (an account
// ARN does not encode its OU), so the confinement rests entirely on the
// destination OU ARNs being the only OU resources listed. If a root ARN or a
// bare wildcard ever appears here, the role can move any account anywhere.
func TestVendorRoleCannotMoveAnAccountOutOfTheSubtree(t *testing.T) {
	r := validRequest()
	cfn, err := VendorRoleCFN(r)
	if err != nil {
		t.Fatalf("VendorRoleCFN: %v", err)
	}
	inMove := false
	for _, line := range strings.Split(string(cfn), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- Sid:") {
			inMove = strings.Contains(trimmed, "MoveAccountsIntoTheDelegatedSubtreeOnly")
			continue
		}
		if !inMove || !strings.Contains(trimmed, "arn:") {
			continue
		}
		if strings.Contains(trimmed, ":root/") {
			t.Errorf("the MoveAccount statement lists a root ARN (%s) — the role could move an "+
				"account to the organization root, out of the delegated subtree and out of "+
				"whatever SCPs bind it", trimmed)
		}
		if strings.Contains(trimmed, ":ou/") && !strings.Contains(trimmed, r.TargetOU) {
			t.Errorf("the MoveAccount statement lists an OU that is not the delegated one: %s", trimmed)
		}
	}
}

// TestVendorRoleCannotMoveAnAccountItDidNotVend is the other half of MoveAccount,
// and it falsifies the README's strongest sentence rather than a scoping detail.
//
// MoveAccount authorizes against the destination parent AND the account being
// moved. The destination is confined to the delegated subtree, which is what the
// README's "cannot place an account anywhere else" claim rests on — and that claim
// is true. The account being moved is the problem: an Organizations account ARN
// encodes the organization, not the account's OU, so the account resource pattern
// is necessarily org-wide. Read together, the statement says "you may move ANY
// account in the organization INTO the delegated OU".
//
// That sounds harmless, because the destination is automat's own OU and automat's
// SCPs only add restrictions. It is not harmless. Moving an account *into* the
// delegated OU also moves it *out of* wherever it was — and the SCPs attached to
// its former parent OU stop applying to it. An account only ever has one parent.
//
// So the attack is: move central IT's production account out from under the OU
// carrying the institutional baseline and into the delegated OU, where only
// automat's SCPs apply. Nothing was updated, deleted, or detached; the baseline SCP
// is untouched and still attached where it always was. The account simply is not
// under it any more. "It cannot loosen anything you enforce" and "Your
// institutional floor holds" are both false, via a statement whose scoping comment
// says it "bounds the blast radius".
//
// The fix is the tag automat already applies at creation: gate MoveAccount on the
// account carrying automat:vended-by. Accounts automat vended can be moved within
// the subtree; accounts it did not vend cannot be moved at all.
func TestVendorRoleCannotMoveAnAccountItDidNotVend(t *testing.T) {
	for name, render := range map[string]func(*Request) ([]byte, error){
		FileRoleCFN: VendorRoleCFN,
		FileRoleTF:  VendorRoleTF,
	} {
		data, err := render(validRequest())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		stmt, ok := statementText(string(data), "MoveAccountsIntoTheDelegatedSubtreeOnly")
		if !ok {
			t.Fatalf("%s: no MoveAccount statement found", name)
		}
		// The statement reaches every account in the organization. That is
		// unavoidable, so it must be paid for with a condition on the account.
		if !strings.Contains(stmt, "aws:ResourceTag/automat:vended-by") {
			t.Errorf("%s: MoveAccount is not gated on aws:ResourceTag/automat:vended-by, so it "+
				"applies to every account in the organization as the account being moved.\n"+
				"The role can move central IT's account out from under the OU holding the "+
				"institutional baseline and into the delegated OU — the baseline SCP is never "+
				"touched, the account is just no longer beneath it. Statement:\n%s", name, stmt)
		}
	}
}

// TestVendorRoleCannotTagOutsideAutomatsNamespace is the tagging question again,
// on the role side. The role holds organizations:TagResource so it can mark the
// accounts it vends. Unrestricted, that is the same escalation as the policy side:
// the role could tag any account or OU in the organization with anything,
// including a tag central IT uses in a condition of its own.
func TestVendorRoleCannotTagOutsideAutomatsNamespace(t *testing.T) {
	for name, render := range map[string]func(*Request) ([]byte, error){
		FileRoleCFN: VendorRoleCFN,
		FileRoleTF:  VendorRoleTF,
	} {
		data, err := render(validRequest())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(data), "organizations:TagResource") {
			continue
		}
		if !strings.Contains(string(data), "aws:TagKeys") {
			t.Errorf("%s grants organizations:TagResource with no aws:TagKeys condition — the role "+
				"could write any tag onto any account or OU in the organization, including one "+
				"central IT relies on in a condition of its own", name)
		}
	}
}

// TestREADMEDescribesTheGrantThatIsActuallyGenerated is the doc-claim tripwire.
//
// Every sentence in README.md is a claim to someone who will approve or refuse
// based on it, and prose drifts silently while code is under test. It said "the
// policy has four statements" for as long as the policy had five, and it described
// the delegation as granting "create, update, attach, and detach" after tagging
// became a fourth grant. Neither is a vulnerability; both are the reviewer finding
// the file does not match the thing they were handed, which spends the credibility
// the blast-radius argument runs on.
//
// So: any count or action list the README states about the generated files is
// checked against those files here.
func TestREADMEDescribesTheGrantThatIsActuallyGenerated(t *testing.T) {
	r := validRequest()
	data, err := README(r)
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	s := string(data)

	// The statement count the README quotes must be the real one.
	n := len(decodePolicy(t, r))
	if want := "five\nstatements in the policy"; n == 5 && !strings.Contains(s, want) {
		t.Errorf("the policy has %d statements but the README does not say so", n)
	} else if n != 5 {
		t.Errorf("the delegation policy now has %d statements, not 5 — the README's count "+
			"and the review checklist both need updating, and this test needs a real "+
			"number-to-word check rather than the special case it has now", n)
	}

	// Every mutating action the policy grants must be named in the README's
	// summary of what the delegation permits, in the reviewer's vocabulary rather
	// than the API's.
	verbs := map[string]string{
		"organizations:CreatePolicy": "create",
		"organizations:UpdatePolicy": "update",
		"organizations:TagResource":  "tag",
		"organizations:AttachPolicy": "attach",
		"organizations:DetachPolicy": "detach",
	}
	for _, stmt := range decodePolicy(t, r) {
		for _, a := range stmt.Action {
			verb, named := verbs[a]
			if named && !strings.Contains(s, verb) {
				t.Errorf("the delegation policy grants %s but the README never says %q — "+
					"a reviewer approving on the README's summary would not know it was "+
					"in there", a, verb)
			}
		}
	}

	// And the conditions the checklist tells a reviewer to look for must exist.
	for _, claim := range []string{"aws:ResourceTag", "aws:RequestTag", "automat:vended-by"} {
		if !strings.Contains(s, claim) {
			t.Errorf("the README's review checklist does not mention %s, which is one of the "+
				"conditions the whole argument rests on", claim)
		}
	}
}

// TestREADMEDisclosesWhatTheDelegateCanDoToAutomatsOwnControls.
//
// The two capabilities here are not escalations and no test above catches them,
// because every test above asks "can the delegate reach central IT's things" and the
// answer is still no. These are about automat's *own* things, and the reason they
// belong in the README is that a reader who accepts the blast-radius argument will
// draw a conclusion from it that is not true.
//
//  1. `DetachPolicy` on automat's own policies means the controls a vended account
//     is born with are not permanent against the account that vended it. Someone
//     approving this bundle as the mechanism by which a research group's accounts
//     stay compliant has read a guarantee that is not in these files. The real
//     answer is `automat verify` re-reading what is attached — which is a different
//     claim, and the README has to make it rather than imply the stronger one.
//  2. `AttachPolicy` on the OU with no cap means the delegate can occupy all five of
//     the SCP slots AWS allows on that target. It weakens nothing, but "I will attach
//     my own policy to that OU later" is a reasonable plan this quietly breaks.
//
// Both assertions are keyed to the actions the policy actually grants, so removing
// the grant retires the disclosure requirement automatically rather than leaving a
// paragraph describing a permission that is gone.
func TestREADMEDisclosesWhatTheDelegateCanDoToAutomatsOwnControls(t *testing.T) {
	r := validRequest()
	data, err := README(r)
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	// Whitespace-normalized, because the README is hard-wrapped prose: a phrase this
	// test looks for can straddle a line break with the next line's bullet indent in
	// the middle of it, and pinning the wrap point would make an editorial reflow
	// fail a security test for no reason.
	s := strings.Join(strings.Fields(string(data)), " ")

	granted := map[string]bool{}
	for _, stmt := range decodePolicy(t, r) {
		for _, a := range stmt.Action {
			granted[a] = true
		}
	}

	if granted["organizations:DetachPolicy"] {
		// "not permanent" is the claim; DetachPolicy is the reason. Asserted on the
		// phrase rather than the sentence so rewording is free and dropping the point
		// is not.
		if !strings.Contains(s, "not permanent") {
			t.Error("the delegation grants organizations:DetachPolicy, so the delegate can remove " +
				"the controls automat attached, and the README does not say so — a reader takes " +
				"the blast-radius section to mean those controls hold")
		}
		if !strings.Contains(s, "automat verify") {
			t.Error("the README says the controls can be detached without naming the answer " +
				"(`automat verify`), which leaves the reader with a problem and no remedy")
		}
	}
	if granted["organizations:AttachPolicy"] && !strings.Contains(s, "five service control policies") {
		t.Error("the delegation grants organizations:AttachPolicy on the OU with no cap on " +
			"how many, and the README does not mention AWS's five-per-target limit — central " +
			"IT can be locked out of attaching a policy at that OU")
	}
}

// conditionKeysRead returns every tag key that any condition in either generated
// document reads, as a set of bare tag keys ("automat:managed-by").
//
// Both documents are scanned as text rather than parsed per-format, because the
// question is not "what shape is this file" but "which tag names does anything in
// this bundle trust". A regex over the rendered output cannot miss a document a
// structural walker was never taught about.
//
// # The character class, and what it used to exclude (AUDIT-2)
//
// This read `(automat:[a-z-]+)`, which excludes digits. One of the three keys in
// mutableTagKeys is automat:artifact-sha256 — writable by design, and the moment any
// condition reads it, the invariant below is what must catch the pair. It would not
// have: the regex truncated the key to "automat:artifact-sha", tagKeyIsWritable's
// explicit-list branch found no grant naming THAT, and the test passed. Verified by
// construction against a synthetic document carrying exactly that read/write pair.
//
// The truncation was inert today, because no condition reads a digit-bearing key. An
// invariant that holds only because nothing has exercised it is not the same as one
// that holds, and this is the test the audit ritual names as the thing standing
// between a shipped bundle and AUDIT-1's C1 coming back.
//
// So the class is now every character AWS permits in a tag key, minus the colon,
// which is the delimiter in both renderings and would swallow the value. Anything
// narrower is a silent narrowing of the invariant rather than of the regex.
//
// The pattern is a package-level var so the negative control below exercises THIS
// one rather than a copy of it. A second literal would reproduce the original defect
// in the very test written to catch it: the control would pass against its own
// widened copy while the enumerator stayed narrow.
var reConditionTagKey = regexp.MustCompile(`aws:(?:Resource|Request)Tag/(automat:[A-Za-z0-9._+=@-]+)`)

func conditionKeysRead(t *testing.T, r *Request) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	for name, render := range allRenderers() {
		data, err := render(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, m := range reConditionTagKey.FindAllStringSubmatch(string(data), -1) {
			keys[m[1]] = true
		}
	}
	return keys
}

// TestNoConditionReadsATagTheBundleLetsTheDelegateWrite is the union check across
// both documents, and it exists because auditing them separately is what let a
// fixed escalation come straight back.
//
// The delegation policy's tag-write grant was hardened to require the target
// already be automat's. The vendor role then granted organizations:TagResource on
// Resource: '*' with only an aws:TagKeys bound of automat:* — which is the same
// forgery, one document over:
//
//  1. Assume the vendor role (by design).
//  2. TagResource on central IT's SCP with automat:managed-by=automat. Permitted:
//     '*' matches a policy ARN and the key matches automat:*.
//  3. Drop back to the member account's delegated credentials. UpdatePolicy and
//     DeletePolicy on that SCP are now gated on a tag that is present.
//
// Same trick with automat:vended-by unlocks MoveAccount against any account in
// the organization, defeating the condition added for exactly that reason.
//
// The rule this encodes: a tag key that any condition in the bundle READS must not
// be writable by any statement in the bundle. Authorization cannot rest on a value
// the authorized party controls, and it does not matter which file the two halves
// live in.
func TestNoConditionReadsATagTheBundleLetsTheDelegateWrite(t *testing.T) {
	r := validRequest()
	read := conditionKeysRead(t, r)
	if len(read) == 0 {
		t.Fatal("no condition keys found; the scanner is broken, not the bundle")
	}

	for name, render := range allRenderers() {
		data, err := render(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, stmt := range tagWritingStatements(string(data)) {
			for key := range read {
				if tagKeyIsWritable(stmt, key) {
					t.Errorf("%s: statement %q may write the tag %q, which a condition somewhere "+
						"in this bundle reads.\n"+
						"A principal that can write the tag a condition checks is not constrained "+
						"by that condition — whichever file the two halves are in.\n%s",
						name, stmt.sid, key, stmt.text)
				}
			}
		}
	}
}

// TestTheEscalationInvariantCanActuallyFail is the negative control the invariant
// above went without, and the reason AUDIT-2 found a hole in it by reading rather
// than by running the suite.
//
// An invariant test that has never been shown to fail is a test whose green is
// uninformative: it is consistent both with "the bundle is sound" and with "the
// machinery no longer looks". The regex truncation was exactly the second case, and
// it survived because nothing ever asked the enumerator to catch a document that
// SHOULD trip it.
//
// So this drives the same two helpers over a synthetic document carrying the pair the
// invariant forbids — one statement gating an action on a tag, another statement able
// to write that same tag — and fails if they report it clean. The key is deliberately
// automat:artifact-sha256, the digit-bearing one, because that is the case the old
// character class dropped.
func TestTheEscalationInvariantCanActuallyFail(t *testing.T) {
	const key = "automat:artifact-sha256"

	// A document in the shape the real renderers produce: two statements, the first
	// reading the tag in a condition, the second granting TagResource with an
	// explicit key list that names it.
	doc := `
        - Sid: ReadsADigitBearingTag
          Effect: Allow
          Action:
            - organizations:UpdatePolicy
          Resource: 'arn:aws:organizations::111122223333:policy/o-x/service_control_policy/*'
          Condition:
            StringEquals:
              aws:ResourceTag/` + key + `: 'abc123'
        - Sid: WritesThatVeryTag
          Effect: Allow
          Action:
            - organizations:TagResource
          Resource: 'arn:aws:organizations::111122223333:account/o-x/*'
          Condition:
            ForAllValues:StringEquals:
              aws:TagKeys:
                - '` + key + `'
`

	var read []string
	for _, m := range reConditionTagKey.FindAllStringSubmatch(doc, -1) {
		read = append(read, m[1])
	}
	if len(read) != 1 || read[0] != key {
		t.Fatalf("the enumerator read %v from a document conditioned on %q — a key it cannot "+
			"extract is a key the invariant cannot check, which is how AUDIT-2's truncation hid",
			read, key)
	}

	stmts := tagWritingStatements(doc)
	if len(stmts) == 0 {
		t.Fatal("tagWritingStatements found no tag-writing statement in a document that grants " +
			"organizations:TagResource; the invariant above cannot fail if this returns nothing")
	}
	var caught bool
	for _, stmt := range stmts {
		if tagKeyIsWritable(stmt, key) {
			caught = true
		}
	}
	if !caught {
		t.Fatalf("the invariant machinery reports NO escalation on a document where a statement can "+
			"write %s and another gates organizations:UpdatePolicy on it. That pair is precisely what "+
			"TestNoConditionReadsATagTheBundleLetsTheDelegateWrite exists to refuse, so its green on "+
			"the real bundle currently proves nothing", key)
	}
}

// TestTheRoleNeverTouchesAPolicy holds the design invariant DESIGN §5 states and
// role.go's own comment claims: no policy actions in the vendor role, those flow
// through the delegation policy. TagResource on Resource: '*' silently broke it,
// because '*' includes every SCP ARN in the organization — the role could not
// change a policy's content, but it could change the tag that decides who may.
func TestTheRoleNeverTouchesAPolicy(t *testing.T) {
	for name, render := range map[string]func(*Request) ([]byte, error){
		FileRoleCFN: VendorRoleCFN,
		FileRoleTF:  VendorRoleTF,
	} {
		data, err := render(validRequest())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, stmt := range tagWritingStatements(string(data)) {
			if strings.Contains(stmt.text, ":policy/") {
				t.Errorf("%s: %q can tag a policy resource", name, stmt.sid)
			}
			// An unscoped resource includes every policy ARN in the organization,
			// which is the same reach written less visibly.
			if reUnscopedResource.MatchString(stmt.text) {
				t.Errorf("%s: %q grants a tag write on an unscoped resource. '*' matches every "+
					"SCP in the organization, so the role can rewrite the tag that decides which "+
					"policies the delegation may modify:\n%s", name, stmt.sid, stmt.text)
			}
		}
	}
}

// reUnscopedResource matches a Resource of exactly "*" in either rendering.
var reUnscopedResource = regexp.MustCompile(`(?m)^\s*Resource\s*[:=]\s*'?"?\*'?"?\s*$`)

// tagStatement is one tag-writing statement found in a rendered document.
type tagStatement struct {
	sid  string
	text string
}

// tagWritingStatements finds every statement in a rendered document that grants a
// tag-writing action, in either the CFN, Terraform, or JSON rendering.
func tagWritingStatements(doc string) []tagStatement {
	var out []tagStatement
	reSid := regexp.MustCompile(`Sid\s*[:=]\s*"?([A-Za-z]+)"?`)
	// Split on Sid boundaries so each chunk is one statement.
	locs := reSid.FindAllStringSubmatchIndex(doc, -1)
	for i, loc := range locs {
		end := len(doc)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		text := doc[loc[0]:end]
		if !strings.Contains(text, "organizations:TagResource") &&
			!strings.Contains(text, "organizations:UntagResource") {
			continue
		}
		out = append(out, tagStatement{sid: doc[loc[2]:loc[3]], text: text})
	}
	return out
}

// tagKeyIsWritable reports whether a tag-writing statement admits the given key.
//
// Conservative on purpose: a statement is treated as admitting the key unless it
// visibly excludes it. An aws:TagKeys bound of automat:* admits every automat key,
// which is the defect; an explicit list admits only what it names.
func tagKeyIsWritable(stmt tagStatement, key string) bool {
	// A statement gated on the resource already carrying automat's owner tag
	// cannot be used to apply that tag to something that does not have it, so it
	// is not a forgery path for the key it is gated on.
	if strings.Contains(stmt.text, "aws:ResourceTag/"+key) {
		return false
	}
	// An explicit key list: writable only if the key is named.
	if strings.Contains(stmt.text, "aws:TagKeys") {
		if strings.Contains(stmt.text, "'"+key+"'") || strings.Contains(stmt.text, `"`+key+`"`) {
			return true
		}
		// A wildcard bound over automat's namespace admits every automat key.
		return strings.Contains(stmt.text, "automat:*")
	}
	return true // No bound at all.
}

// allRenderers is every file the bundle generates, for tests that must not miss
// one when a renderer is added.
func allRenderers() map[string]func(*Request) ([]byte, error) {
	return map[string]func(*Request) ([]byte, error){
		FilePolicy:  DelegationPolicy,
		FileRoleCFN: VendorRoleCFN,
		FileRoleTF:  VendorRoleTF,
		FileREADME:  README,
		FileOU:      OUInstructions,
	}
}

// TestTheRoleCanOnlyTagAccountsItVended closes the residual reach left by scoping
// TagResource: an Organizations account ARN encodes the organization, not the OU, so
// "account/<org>/*" is every account in the organization however the OU is spelled.
//
// The keys are inventory labels no condition reads, so forging one escalates
// nothing — but writing tags onto central IT's own accounts is reach the vend
// pipeline never needs, and "it is only a cost-allocation tag" is a sentence that
// stops being true the first time someone builds a report on it. Accounts the role
// vended already carry automat:vended-by (applied at CreateAccount, where the value
// is fixed by the template), so the condition costs nothing legitimate.
//
// OUs are handled by a separate statement: a freshly created OU carries no tags at
// all, so a resource-tag condition would make tagging one impossible. Its resource
// bound is the delegated subtree, which is a real bound — unlike the account ARN.
func TestTheRoleCanOnlyTagAccountsItVended(t *testing.T) {
	for name, render := range map[string]func(*Request) ([]byte, error){
		FileRoleCFN: VendorRoleCFN,
		FileRoleTF:  VendorRoleTF,
	} {
		data, err := render(validRequest())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, stmt := range tagWritingStatements(string(data)) {
			if !strings.Contains(stmt.text, ":account/") {
				continue // an OU-only statement; the subtree bound confines it
			}
			if !strings.Contains(stmt.text, "aws:ResourceTag/automat:vended-by") {
				t.Errorf("%s: %q can tag an account but is not conditioned on "+
					"automat:vended-by. account/<org>/* is every account in the organization, "+
					"so this writes tags onto accounts central IT owns:\n%s",
					name, stmt.sid, stmt.text)
			}
		}
	}
}

// yamlCoercingValues are plain YAML scalars that a 1.1 parser resolves to a
// non-string type. CloudFormation's parser is in this family, so an operator-supplied
// value landing unquoted in a scalar position does not arrive as the string that was
// validated.
var yamlCoercingValues = []string{
	"No", "no", "n", "N", "yes", "y", "on", "off", "Off", "OFF",
	"true", "false", "null", "NULL",
	"0755", "0x1F", "12345678", "1e5", "1.0", "0",
	"2026-01-01",
}

// TestOperatorValuesSurviveTheYAMLParserAsStrings covers the gap between "the input
// is safe" and "the input means what it said".
//
// Request.Validate is an allowlist, and it is doing its job: none of these values
// can terminate a string or open a substitution. But every one of them is also a
// legal role name AND a YAML 1.1 non-string literal, so `--vendor-role-name off`
// written unquoted becomes the boolean false in the deployed template. The operator
// then has a role named something other than what they asked for, automat's config
// points at a role ARN that does not exist, and the failure surfaces later as a
// permission error with no connection to its cause.
//
// Validation cannot fix this, and it should not try: "off" is a reasonable role
// name, and a denylist of YAML's type-resolution rules is a list that grows with
// every parser. The renderer quotes instead.
//
// # What this test does and does not prove
//
// It matches bytes; it does not run a YAML parser, because there is no YAML parser in
// the dependency tree and adding one needs the human's approval (CLAUDE.md working
// style). That is sound only because of a second fact, and the dependency is stated
// here rather than left implicit: a single-quoted YAML scalar is unconditionally a
// string in both 1.1 and 1.2, so the quoted form needs no parser to be checked — but
// only if the value cannot contain a `'` and close the quote itself.
// TestNoPatternAdmitsAStructuralCharacter is what establishes that, by brute force
// over every byte. If either half is ever weakened, this test keeps passing while its
// claim stops being true, which is why the two are cross-referenced.
func TestOperatorValuesSurviveTheYAMLParserAsStrings(t *testing.T) {
	for _, v := range yamlCoercingValues {
		r := validRequest()
		r.VendorRoleName = v
		data, err := VendorRoleCFN(r)
		if err != nil {
			t.Fatalf("VendorRoleCFN(%q): %v", v, err)
		}
		// The RoleName line specifically, not a Contains over the whole document: the
		// same value also appears in the template's description and in a resource
		// name, so a document-wide match could be satisfied by an occurrence that is
		// not the scalar CloudFormation reads as the role's name.
		line, ok := findKeyLine(string(data), "RoleName:")
		if !ok {
			t.Fatalf("VendorRoleCFN(%q) rendered no RoleName line at all", v)
		}
		if want := "RoleName: '" + v + "'"; line != want {
			t.Errorf("vendor role name %q renders as %q, want %q.\n"+
				"Unquoted, a YAML 1.1 parser resolves this to a non-string and the deployed "+
				"role is not the one that was requested.", v, line, want)
		}
	}
}

// findKeyLine returns the first line whose trimmed text starts with key.
func findKeyLine(doc, key string) (string, bool) {
	for _, l := range strings.Split(doc, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, key) {
			return t, true
		}
	}
	return "", false
}

// TestNoOperatorValueLandsUnquotedInAStructuredField generalizes the previous test
// from the one field that had the bug to every field that could.
//
// The concrete finding was RoleName rendered as a bare YAML scalar. The class is
// broader: an operator-supplied value reaching a structured position — a YAML scalar,
// an HCL attribute — must be quoted, or the document's parser gets to decide its
// type. This walks every field with a distinctive marker value and checks that each
// occurrence in a structured line is quoted, so a renderer added later cannot
// reintroduce the same mistake in a new field.
//
// Prose lines are exempt: a role name in an English sentence in a comment is not
// parsed as anything.
func TestNoOperatorValueLandsUnquotedInAStructuredField(t *testing.T) {
	// Markers are valid for their field and unlikely to occur incidentally.
	fields := []struct {
		name   string
		marker string
		set    func(*Request, string)
	}{
		{"vendor_role_name", "Zmarkerrole", func(r *Request, v string) { r.VendorRoleName = v }},
		{"target_ou_name", "Zmarkerouname", func(r *Request, v string) {
			r.TargetOU = ""
			r.TargetOUName = v
		}},
	}
	for _, f := range fields {
		for name, render := range map[string]func(*Request) ([]byte, error){
			FileRoleCFN: VendorRoleCFN,
			FileRoleTF:  VendorRoleTF,
		} {
			r := validRequest()
			f.set(r, f.marker)
			data, err := render(r)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, f.name, err)
			}
			for i, line := range strings.Split(string(data), "\n") {
				if !strings.Contains(line, f.marker) {
					continue
				}
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue // a comment; not parsed
				}
				// A structured line assigns a value: "Key: v" or "key = v".
				if !reStructuredAssign.MatchString(trimmed) {
					continue // prose inside a description block
				}
				if !strings.Contains(line, "'"+f.marker) && !strings.Contains(line, `"`+f.marker) {
					t.Errorf("%s line %d: %s lands unquoted in a structured field:\n  %s\n"+
						"The document's parser decides the type of a bare scalar, so the "+
						"deployed value is not necessarily the validated string.",
						name, i+1, f.name, trimmed)
				}
			}
		}
	}
}

// reStructuredAssign matches a line that assigns a value in YAML or HCL, as opposed
// to a line of prose that happens to contain one.
var reStructuredAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*(?::|=)\s*\S`)
