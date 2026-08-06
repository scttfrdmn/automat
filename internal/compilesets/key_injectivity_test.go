// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"sort"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Injectivity of the packer's canonical keys, which is what makes the merge decision
// trustworthy (AUDIT-2 H5).
//
// guardKey and statementKey were built by joining fields on control bytes, which is not
// an injective encoding, and a collision in a key that decides which prohibitions MERGE
// is a widening rather than a cosmetic bug. These drive the encoding directly, because
// the collisions are properties of the key function and asserting on it is what makes
// the property checkable without first building a document that has to survive schema
// validation.
//
// The durable pin for the same property is the widened vocabulary in
// merge_property_test.go — probeResources now carries the multi-member, separator-bearing
// and empty shapes a collision needs, so TestUnionIsMonotone can reach this defect class.
// These tests are the narrow companion to it: they name the exact collisions and say what
// each one cost.
//
// AUDIT-2 H5: guardKey and statementKey were built by joining fields on control bytes,
// which is not an injective encoding, and a collision in a key that decides which
// prohibitions MERGE is a widening rather than a cosmetic bug. These drive the encoding
// directly, because the collisions are properties of the key function and asserting on
// it is what makes the fix checkable without first building a document that has to
// survive schema validation.

// jamStmt is the embedded-struct boilerplate, once.
func jamStmt(effect string, action, resource []string, cond artifact.Condition, ex artifact.ExemptPrincipals) Statement {
	return Statement{SCPStatement: artifact.SCPStatement{
		Effect:           effect,
		Action:           action,
		Resource:         resource,
		Condition:        cond,
		ExemptPrincipals: ex,
	}}
}

func cond1(op, key string, vals ...string) artifact.Condition {
	return artifact.Condition{op: {key: vals}}
}

// preFixGuardKey and preFixConditionKey are the encoding as it stood at HEAD, copied
// here rather than reached by editing merge.go.
//
// A counter-check has to show the collisions were REAL, not merely that the new
// encoding is injective — an assertion that two keys differ passes trivially against a
// function that has never collided. The earlier instinct was to strip the fix and
// re-run; that is the wrong move on a security fix, because for the length of the run
// the repository contains the vulnerability and a test that says it is fine. A replica
// answers the same question and leaves production code alone.
func preFixGuardKey(st Statement) string {
	return strings.Join([]string{
		st.Effect,
		strings.Join(sortedUnique(st.Resource), "\x01"),
		preFixConditionKey(st.Condition),
	}, "\x00")
}

func preFixConditionKey(c artifact.Condition) string {
	if len(c) == 0 {
		return ""
	}
	ops := make([]string, 0, len(c))
	for op := range c {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	var sb strings.Builder
	for _, op := range ops {
		sb.WriteString(op)
		sb.WriteString("\x02")
		keys := make([]string, 0, len(c[op]))
		for k := range c[op] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteString(k)
			sb.WriteString("\x03")
			sb.WriteString(strings.Join(sortedUnique(c[op][k]), "\x01"))
			sb.WriteString("\x04")
		}
	}
	return sb.String()
}

// The collisions the audit reproduced, as key-level assertions.
func TestGuardKeyIsInjectiveOverTheShapesThatCollided(t *testing.T) {
	roleA := "arn:aws:iam::111122223333:role/A"
	roleB := "arn:aws:iam::111122223333:role/B"

	cases := []struct {
		name string
		a, b Statement
	}{
		{
			// One resource value carrying the list separator, against two real
			// members. The JSON decoder happens to refuse a raw control byte in a
			// string, which is the decoder's accident and not this function's
			// guarantee.
			name: "a separator inside a resource",
			a:    jamStmt("Deny", nil, []string{roleA + "\x01" + roleB}, nil, nil),
			b:    jamStmt("Deny", nil, []string{roleA, roleB}, nil, nil),
		},
		{
			// No control byte anywhere, and the one that neutralized a root-user
			// Deny in the probe. An empty resource string joins to "", which is
			// what an absent list joins to.
			name: "an empty resource string against an absent resource",
			a:    jamStmt("Deny", nil, []string{""}, nil, nil),
			b:    jamStmt("Deny", nil, nil, nil, nil),
		},
		{
			// The same shape one level down, also with no control byte.
			name: "an empty condition value against an absent one",
			a:    jamStmt("Deny", nil, nil, cond1("StringLike", "aws:PrincipalArn", ""), nil),
			b:    jamStmt("Deny", nil, nil, cond1("StringLike", "aws:PrincipalArn"), nil),
		},
		{
			name: "a separator inside a condition value",
			a:    jamStmt("Deny", nil, nil, cond1("StringLike", "aws:PrincipalArn", roleA+"\x01"+roleB), nil),
			b:    jamStmt("Deny", nil, nil, cond1("StringLike", "aws:PrincipalArn", roleA, roleB), nil),
		},
		{
			// The structural separators were forgeable too: one condition key whose
			// name carries the key/value separators keys the same as two condition
			// keys. So a guard requiring BOTH a principal and a source IP keys the
			// same as one requiring a nonsense single key — and merging across them
			// applies the actions under whichever guard seeded the group.
			name: "two condition keys against one carrying the separators",
			a: jamStmt("Deny", nil, nil, artifact.Condition{
				"StringLike": {"aws:PrincipalArn": {roleA}, "aws:SourceIp": {"10.0.0.0/8"}},
			}, nil),
			b: jamStmt("Deny", nil, nil, cond1("StringLike",
				"aws:PrincipalArn\x03"+roleA+"\x04aws:SourceIp", "10.0.0.0/8"), nil),
		},
		{
			// And an operator name carrying the operator separator keys the same as
			// a condition key carrying it.
			name: "a separator inside a condition operator",
			a:    jamStmt("Deny", nil, nil, cond1("StringLike\x02aws:PrincipalArn", "x", roleA), nil),
			b:    jamStmt("Deny", nil, nil, cond1("StringLike", "aws:PrincipalArn\x02x", roleA), nil),
		},
		{
			// Cross-FIELD bleed, not just cross-member: the three fields were joined
			// on "\x00" as well, so a value carrying one crosses a field boundary. An
			// effect that swallows the resource slot keys identically to a resource
			// that swallows the condition slot. The schema's effect enum refuses this
			// particular value today, which is exactly the kind of thing the key
			// should not be resting on, since the key is what the merge trusts.
			name: "a separator across a field boundary",
			a:    jamStmt("Deny\x00"+roleA, nil, nil, nil, nil),
			b:    jamStmt("Deny", nil, []string{roleA + "\x00"}, nil, nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// First: the pre-fix encoding really did collide on this pair. If it
			// did not, this case is not exercising the finding and proves nothing
			// about the fix.
			if pa, pb := preFixGuardKey(tc.a), preFixGuardKey(tc.b); pa != pb {
				t.Fatalf("the PRE-FIX encoding did not collide here, so this case does not exercise "+
					"H5:\n  a = %q\n  b = %q", pa, pb)
			} else {
				t.Logf("CONFIRMED PRE-FIX COLLISION: both guards keyed as %q", pa)
			}

			ka, kb := guardKey(tc.a), guardKey(tc.b)
			if ka == kb {
				t.Fatalf("guardKey COLLIDES, so these two guards merge and the merged statement "+
					"carries the union of their actions under one of their scopes:\n  key = %q", ka)
			}
			t.Logf("distinct:\n  a = %q\n  b = %q", ka, kb)

			// statementKey too: it drives sortStatements and derivedSid, so a
			// collision there gives two different statements one Sid — which IAM
			// rejects as MalformedPolicyDocument, mid-vend.
			if sa, sb := statementKey(tc.a), statementKey(tc.b); sa == sb {
				t.Errorf("statementKey COLLIDES; derivedSid would label both statements the same:\n"+
					"  key = %q", sa)
			}
		})
	}
}

// The other axes of statementKey. The action pattern is not refused a control byte at
// the artifact layer, so the key is what has to make one harmless.
func TestStatementKeyIsInjectiveOverActionsAndExemptions(t *testing.T) {
	pairs := []struct {
		name string
		a, b Statement
	}{
		{
			"a separator inside an action",
			jamStmt("Deny", []string{"iam:DeleteRole\x00zzz:Nothing"}, nil, nil, nil),
			jamStmt("Deny", []string{"iam:DeleteRole", "zzz:Nothing"}, nil, nil, nil),
		},
		{
			"an empty action against no action",
			jamStmt("Deny", []string{""}, nil, nil, nil),
			jamStmt("Deny", nil, nil, nil, nil),
		},
		{
			// The two allowlist statements are both "Deny, Resource *, no Action",
			// distinguished only by which field carries the list.
			"an action against the same list as NotAction",
			jamStmt("Deny", []string{"s3:*"}, nil, nil, nil),
			Statement{NotAction: []string{"s3:*"}, SCPStatement: artifact.SCPStatement{Effect: "Deny"}},
		},
		{
			"an empty exempt principal against none",
			jamStmt("Deny", []string{"s3:*"}, nil, nil, artifact.ExemptPrincipals{{Principal: "", Reason: "x"}}),
			jamStmt("Deny", []string{"s3:*"}, nil, nil, nil),
		},
		{
			"a separator inside an exempt principal",
			jamStmt("Deny", []string{"s3:*"}, nil, nil, artifact.ExemptPrincipals{
				{Principal: "a\x00b", Reason: "x"},
			}),
			jamStmt("Deny", []string{"s3:*"}, nil, nil, artifact.ExemptPrincipals{
				{Principal: "a", Reason: "x"}, {Principal: "b", Reason: "y"},
			}),
		},
	}
	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			if ka, kb := statementKey(tc.a), statementKey(tc.b); ka == kb {
				t.Fatalf("statementKey COLLIDES:\n  key = %q", ka)
			}
		})
	}
}

// The end-to-end shape through mergeStatements and the renderer: the probe's root-user
// Deny, neutralized by an empty resource string with no control byte in the document.
//
// The root Deny names NO resource, which is the ordinary shape — renderStatement
// supplies "*" for a Deny that did not narrow one (pack.go). A decoy naming Resource
// [""] keyed identically pre-fix, because both join to the empty string, and a
// guardGroup takes its guard from whichever statement seeded it. So the merged
// statement carries Resource [""] — which renders literally, matches nothing, and is
// still there in the document an operator reads.
func TestAnEmptyResourceNoLongerNeutralizesARootDeny(t *testing.T) {
	rootGuard := cond1("StringLike", "aws:PrincipalArn", "arn:aws:iam::*:root")
	rootDeny := jamStmt("Deny", []string{"iam:CreateUser"}, nil, rootGuard, nil)
	decoy := jamStmt("Deny", []string{"zzz:Nothing"}, []string{""}, rootGuard, nil)

	// The pre-fix consequence, shown rather than described. Feeding the real
	// guardGroup by hand is exactly what the old key caused; nothing here
	// reimplements the merge, and production code is untouched.
	if preFixGuardKey(rootDeny) != preFixGuardKey(decoy) {
		t.Fatalf("the pre-fix encoding did not collide on this pair, so this test does not exercise H5")
	}
	var sawNeutralized bool
	for _, order := range [][2]Statement{{rootDeny, decoy}, {decoy, rootDeny}} {
		g := &guardGroup{template: order[0], actions: map[string]*actionFacts{}}
		g.add(order[0])
		g.add(order[1])
		got := g.statements()
		if len(got) != 1 {
			t.Fatalf("one group must render one statement here, got %d", len(got))
		}
		t.Logf("PRE-FIX MERGE (seeded by Resource=%#v): Resource=%#v Action=%q",
			order[0].Resource, got[0].Resource, got[0].Action)
		if len(got[0].Resource) == 1 && got[0].Resource[0] == "" && contains(got[0].Action, "iam:CreateUser") {
			sawNeutralized = true
			t.Log("  CONFIRMED PRE-FIX WIDENING: the root-user Deny on iam:CreateUser now names " +
				"Resource [\"\"], which matches nothing — the prohibition is present in the document " +
				"and inert. Rendered, that is a literal empty resource, not the \"*\" the unmerged " +
				"statement would have got.")
		}
	}
	if !sawNeutralized {
		t.Error("the pre-fix merge never produced the neutralized form in either seeding order; the " +
			"finding as written is not reproduced by this test")
	}

	// Post-fix: the two guards no longer merge, so both prohibitions keep the scope
	// their catalog gave them.
	merged := mergeStatements([]Statement{rootDeny, decoy})
	var survived bool
	for _, st := range merged {
		if !contains(st.Action, "iam:CreateUser") {
			continue
		}
		switch {
		case len(st.Resource) == 0:
			survived = true
		case len(st.Resource) == 1 && st.Resource[0] == "":
			t.Errorf("the root Deny's action still lands on an EMPTY resource: %+v", st.SCPStatement)
		default:
			t.Errorf("the root Deny picked up a resource it did not have: %+v", st.SCPStatement)
		}
	}
	if !survived {
		t.Fatalf("the root-user Deny did not survive the merge with its own (unnarrowed) scope: %+v", merged)
	}
	if len(merged) != 2 {
		t.Errorf("want 2 statements (the guards differ), got %d: %+v", len(merged), merged)
	}
	if merged[0].Sid == merged[1].Sid {
		t.Errorf("two statements share a Sid, which IAM rejects as MalformedPolicyDocument: %s", merged[0].Sid)
	}
}

// The must-still-work half. Statements that SHOULD merge still do — the packer exists
// for the quota relief and a fix that cost it would be a regression, not a hardening.
func TestRealMergesStillHappen(t *testing.T) {
	guard := cond1("StringLike", "aws:PrincipalArn", "arn:aws:iam::*:root")
	a := jamStmt("Deny", []string{"iam:DeleteRole"}, []string{"*"}, guard, nil)
	b := jamStmt("Deny", []string{"iam:PutRolePolicy"}, []string{"*"}, guard, nil)

	merged := mergeStatements([]Statement{a, b})
	if len(merged) != 1 {
		t.Fatalf("two statements sharing a guard and an exemption set must merge into one, got %d: %+v",
			len(merged), merged)
	}
	if len(merged[0].Action) != 2 {
		t.Errorf("the merged statement must carry both actions: %+v", merged[0].SCPStatement)
	}

	// Same guard, differing exemptions: the intersection axis. Still one statement.
	ex := jamStmt("Deny", []string{"iam:DeleteRole"}, []string{"*"}, guard,
		artifact.ExemptPrincipals{{Principal: artifact.AutomationRolePlaceholder, Reason: "baseline"}})
	if got := mergeStatements([]Statement{a, ex}); len(got) != 1 {
		t.Errorf("same action, differing exemptions must intersect to one statement, got %d: %+v", len(got), got)
	} else if len(got[0].ExemptPrincipals) != 0 {
		t.Errorf("the exemption present in only one input must not survive the intersection: %+v",
			got[0].ExemptPrincipals)
	}

	// Order- and duplicate-invariance, which sortedUnique provides and the length
	// prefix must not disturb — Merge is commutative by the property tests and that
	// rests on this.
	k1 := guardKey(jamStmt("Deny", nil, []string{"a", "b", "a"}, nil, nil))
	k2 := guardKey(jamStmt("Deny", nil, []string{"b", "a"}, nil, nil))
	if k1 != k2 {
		t.Errorf("guardKey is not order/duplicate invariant:\n  %q\n  %q", k1, k2)
	}
	if !strings.HasPrefix(k1, "4:Deny") {
		t.Errorf("the key does not look length-prefixed: %q", k1)
	}
}
