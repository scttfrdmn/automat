// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
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
