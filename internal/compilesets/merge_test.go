// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Table-driven tests for the merge axes, plus the tests that keep the property
// suite honest.
//
// The property tests in merge_property_test.go check that no merge widens. These
// check the complementary thing a property test cannot: that the merges the
// package claims to perform actually happen. A merger that refused every merge
// would satisfy every property in that file — monotonically, commutatively, and
// associatively — while being useless against the 5-policy quota that is the whole
// reason the packer exists.

// mustMerge, mustCombine, and mustFromArtifact wrap the now-fallible
// Merge/Combine/FromArtifact for the ordinary case in a test where the
// inputs are not expected to conflict — the same shape mustPack (pack_test.go)
// already gives Pack. Tests specifically exercising a Config-rule conflict
// call the functions directly to inspect the error.
func mustMerge(t *testing.T, artifacts ...*artifact.Artifact) *Merged {
	t.Helper()
	m, err := Merge(artifacts...)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	return m
}

func mustCombine(t *testing.T, a, b *Merged) *Merged {
	t.Helper()
	m, err := Combine(a, b)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	return m
}

func mustFromArtifact(t *testing.T, a *artifact.Artifact) *Merged {
	t.Helper()
	m, err := FromArtifact(a)
	if err != nil {
		t.Fatalf("FromArtifact: %v", err)
	}
	return m
}

// deny builds a statement fragment for a table entry.
func deny(sid string, actions []string, resource []string, cond artifact.Condition, exempt ...artifact.ExemptPrincipal) Statement {
	return Statement{
		SCPStatement: cloneStatement(artifact.SCPStatement{
			Sid:              sid,
			Effect:           "Deny",
			Action:           actions,
			Resource:         resource,
			Condition:        cond,
			ExemptPrincipals: artifact.ExemptPrincipals(exempt).Canonical(),
		}),
		Origins: []string{"set:" + sid},
	}
}

func exempt(principal, reason string) artifact.ExemptPrincipal {
	return artifact.ExemptPrincipal{Principal: principal, Reason: reason}
}

const (
	breakGlass = "arn:aws:iam::111111111111:role/break-glass"
	centralIT  = "arn:aws:iam::111111111111:role/central-it"
)

var regionCond = artifact.Condition{"StringNotEquals": {"aws:RequestedRegion": {"us-east-1"}}}

func TestTheTwoMergeAxes(t *testing.T) {
	tests := []struct {
		name string
		a, b Statement
		// want is the number of statements after the merge: 1 if they merged.
		want int
		// check inspects the result when they merged into one.
		check func(t *testing.T, got Statement)
		// checkAll inspects the whole result, for the cases where "did not merge"
		// is not the interesting part — what each surviving statement CARRIES is.
		checkAll func(t *testing.T, got []Statement)
		why      string
	}{
		{
			name: "same actions different exemptions intersect",
			a:    deny("A", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil, exempt(breakGlass, "incident response")),
			b:    deny("B", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil),
			want: 1,
			why:  "axis 1: the exemption survives only if both sides granted it",
			check: func(t *testing.T, got Statement) {
				if len(got.ExemptPrincipals) != 0 {
					t.Errorf("exemptions must intersect to nothing here, got %v", got.ExemptPrincipals)
				}
			},
		},
		{
			name: "same exemptions different actions union",
			a:    deny("A", []string{"cloudtrail:StopLogging"}, []string{"*"}, nil, exempt(centralIT, "log management")),
			b:    deny("B", []string{"cloudtrail:DeleteTrail"}, []string{"*"}, nil, exempt(centralIT, "log management")),
			want: 1,
			why:  "axis 2: each action keeps the identical guard it arrived with, so nothing moves",
			check: func(t *testing.T, got Statement) {
				if len(got.Action) != 2 {
					t.Errorf("actions must union, got %v", got.Action)
				}
				if len(got.ExemptPrincipals) != 1 {
					t.Errorf("the shared exemption must survive, got %v", got.ExemptPrincipals)
				}
			},
		},
		{
			name: "both axes at once keeps each action's own exemptions",
			a:    deny("A", []string{"cloudtrail:StopLogging"}, []string{"*"}, nil, exempt(breakGlass, "incident response")),
			b:    deny("B", []string{"cloudtrail:DeleteTrail"}, []string{"*"}, nil),
			want: 2,
			why: "the two actions have different exemption sets, so they cannot share a statement: merging " +
				"them would give StopLogging the empty list and DeleteTrail the break-glass hole, or the " +
				"reverse — over-strict on one action or WIDENED on the other. The normal form keeps them " +
				"apart per action rather than refusing to look at the pair",
			checkAll: func(t *testing.T, got []Statement) {
				// Not merely "did not merge": each action must still carry exactly
				// the exemptions its own control set granted. A normal form that
				// grouped by statement instead of by action could produce two
				// statements with the wrong exemptions on each.
				for _, st := range got {
					switch st.Action[0] {
					case "cloudtrail:StopLogging":
						if len(st.ExemptPrincipals) != 1 || st.ExemptPrincipals[0].Principal != breakGlass {
							t.Errorf("StopLogging lost its break-glass exemption: %v", st.ExemptPrincipals)
						}
					case "cloudtrail:DeleteTrail":
						if len(st.ExemptPrincipals) != 0 {
							t.Errorf("DeleteTrail gained an exemption nobody granted: %v", st.ExemptPrincipals)
						}
					}
				}
			},
		},
		{
			name: "one action shared, one not, with differing exemptions",
			a: deny("A", []string{"config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder"},
				[]string{"*"}, nil, exempt(breakGlass, "incident response")),
			b:    deny("B", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil),
			want: 2,
			why: "StopConfigurationRecorder is constrained by both sides and only one granted the hole, so " +
				"its exemption intersects away; DeleteConfigurationRecorder is constrained by A alone and " +
				"keeps A's exemption. The two actions then have different exemption sets and cannot share " +
				"a statement — this is the case the old pairwise merger skipped entirely",
			checkAll: func(t *testing.T, got []Statement) {
				for _, st := range got {
					switch st.Action[0] {
					case "config:DeleteConfigurationRecorder":
						if len(st.ExemptPrincipals) != 1 {
							t.Errorf("only A constrains DeleteConfigurationRecorder, so its exemption stands: %v",
								st.ExemptPrincipals)
						}
					case "config:StopConfigurationRecorder":
						if len(st.ExemptPrincipals) != 0 {
							t.Errorf("B constrains StopConfigurationRecorder without exempting anyone, so the "+
								"hole must close: %v", st.ExemptPrincipals)
						}
					}
				}
			},
		},
		{
			name: "different resource does not merge",
			a:    deny("A", []string{"s3:PutBucketPolicy"}, []string{"*"}, nil),
			b:    deny("B", []string{"s3:PutBucketPolicy"}, []string{"arn:aws:s3:::institution-*"}, nil),
			want: 2,
			why: "a different resource is a different scope; one statement over the union of actions at " +
				"the wider resource would deny more, and at the narrower would deny less",
		},
		{
			name: "different condition does not merge",
			a:    deny("A", []string{"s3:PutBucketPolicy"}, []string{"*"}, nil),
			b:    deny("B", []string{"s3:PutBucketPolicy"}, []string{"*"}, regionCond),
			want: 2,
			why: "a different condition is a different guard: combining would apply the union of the " +
				"actions under whichever guard was kept, and keeping the weaker one WIDENS",
		},
		{
			name: "identical statements dedupe",
			a:    deny("A", []string{"iam:CreateUser"}, []string{"*"}, nil),
			b:    deny("B", []string{"iam:CreateUser"}, []string{"*"}, nil),
			want: 1,
			why:  "two frameworks requiring the same Deny is the normal case; it must not cost two policy slots",
			check: func(t *testing.T, got Statement) {
				if len(got.Origins) != 2 {
					t.Errorf("both frameworks must appear in the provenance, got %v", got.Origins)
				}
			},
		},
		{
			name: "differing Sid does not prevent a dedupe",
			a:    deny("FrameworkOneNaming", []string{"iam:CreateUser"}, []string{"*"}, nil),
			b:    deny("FrameworkTwoNaming", []string{"iam:CreateUser"}, []string{"*"}, nil),
			want: 1,
			why: "a Sid is a naming choice, not a semantic difference; keying on it would spend a policy " +
				"slot per framework on a Deny they share",
		},
		{
			name: "one exemption each, disjoint, intersects to nothing",
			a:    deny("A", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil, exempt(breakGlass, "incident response")),
			b:    deny("B", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil, exempt(centralIT, "operations")),
			want: 1,
			why:  "neither side agreed to the other's hole",
			check: func(t *testing.T, got Statement) {
				if len(got.ExemptPrincipals) != 0 {
					t.Errorf("disjoint exemption lists must intersect to nothing, got %v — concatenating "+
						"them would grant each control set the other's hole", got.ExemptPrincipals)
				}
			},
		},
		{
			name: "overlapping exemptions keep only the shared one",
			a: deny("A", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil,
				exempt(breakGlass, "incident response"), exempt(centralIT, "operations")),
			b: deny("B", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil,
				exempt(breakGlass, "audited procedure")),
			want: 1,
			why:  "the intersection is the one principal both sides named",
			check: func(t *testing.T, got Statement) {
				if len(got.ExemptPrincipals) != 1 || got.ExemptPrincipals[0].Principal != breakGlass {
					t.Fatalf("expected only %s to survive, got %v", breakGlass, got.ExemptPrincipals)
				}
				for _, want := range []string{"incident response", "audited procedure"} {
					if !strings.Contains(got.ExemptPrincipals[0].Reason, want) {
						t.Errorf("the merged reason %q drops a justification (%q)",
							got.ExemptPrincipals[0].Reason, want)
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeStatements([]Statement{tc.a, tc.b})
			if len(got) != tc.want {
				t.Fatalf("expected %d statement(s), got %d — %s\n%s",
					tc.want, len(got), tc.why, describe("merged", &Merged{Statements: got}))
			}
			if tc.want == 1 && tc.check != nil {
				tc.check(t, got[0])
			}
			if tc.checkAll != nil {
				tc.checkAll(t, got)
			}
		})
	}
}

// TestAChainOfStatementsCollapsesCompletely.
//
// Four statements differing only in their action lists must become one. A merger
// that stopped short would leave a policy larger than necessary, which under the
// 5-per-target quota is not cosmetic — it is the difference between a vend that
// attaches and one that parks the account.
func TestAChainOfStatementsCollapsesCompletely(t *testing.T) {
	in := []Statement{
		deny("A", []string{"cloudtrail:StopLogging"}, []string{"*"}, nil),
		deny("B", []string{"cloudtrail:DeleteTrail"}, []string{"*"}, nil),
		deny("C", []string{"cloudtrail:UpdateTrail"}, []string{"*"}, nil),
		deny("D", []string{"cloudtrail:PutEventSelectors"}, []string{"*"}, nil),
	}
	got := mergeStatements(in)
	if len(got) != 1 {
		t.Fatalf("four statements differing only in their action lists must collapse to one, got %d:\n%s",
			len(got), describe("merged", &Merged{Statements: got}))
	}
	if len(got[0].Action) != 4 {
		t.Errorf("expected all four actions, got %v", got[0].Action)
	}
	if len(got[0].Origins) != 4 {
		t.Errorf("expected all four origins, got %v", got[0].Origins)
	}
}

// TestNoAllowlistStatementIsEverMerged.
//
// Promised by name in Statement.NotAction's doc comment, in regionStatement's, and
// in the package comment, so it is owed by the code as it stands.
//
// A Deny over NotAction denies everything it does not name, so it is not
// describable by the per-action exemption map mergeStatements normalizes to, and
// two of them combined into one statement would deny either more than the pair
// (a deny-all that bricks the account) or less (a widening). So they never enter
// the normal form: the packer appends them after mergeStatements runs, and
// mergeStatements passes any it is handed straight through if that ordering ever
// changes.
func TestNoAllowlistStatementIsEverMerged(t *testing.T) {
	region := regionStatement(newAllowSet([]string{"us-east-1"}, "set:regions"), testGlobalNamespaces, PackOptions{})
	service := serviceStatement(newAllowSet([]string{"s3"}, "set:services"), testGlobalNamespaces, PackOptions{})

	t.Run("two allowlist statements pass through untouched", func(t *testing.T) {
		got := mergeStatements([]Statement{region, service})
		if len(got) != 2 {
			t.Fatalf("two NotAction statements collapsed into %d; the result denies everything outside one "+
				"of the two lists, which either widens or denies every call in the account:\n%s",
				len(got), describe("merged", &Merged{Statements: got}))
		}
		for _, st := range got {
			if !st.isAllowlist() {
				t.Errorf("statement %q lost its NotAction list", st.Sid)
			}
			if len(st.Action) > 0 {
				t.Errorf("statement %q gained an Action list alongside NotAction, which IAM cannot "+
					"evaluate", st.Sid)
			}
		}
	})

	t.Run("an allowlist does not absorb an ordinary statement", func(t *testing.T) {
		// The adversarial pair: an ordinary Deny whose actions are exactly the
		// allowlist's NotAction entries, under the same guard. Anything that keyed
		// on the guard alone and then unioned "the action list" would merge these.
		ordinary := deny("A", region.NotAction, []string{"*"}, region.Condition)
		got := mergeStatements([]Statement{region, ordinary})
		if len(got) != 2 {
			t.Fatalf("a NotAction statement merged with an Action statement over the same guard:\n%s",
				describe("merged", &Merged{Statements: got}))
		}
		// And in the other order, because a pass-through that depended on arrival
		// order would be caught by nothing else here.
		if got := mergeStatements([]Statement{ordinary, region}); len(got) != 2 {
			t.Fatalf("the refusal is not symmetric: %d statement(s)", len(got))
		}
	})

	t.Run("two service allowlists over different namespaces both survive", func(t *testing.T) {
		// Both are "Deny, Resource *, no Action" and differ only in NotAction. A
		// statementKey omitting the field would collapse them into whichever
		// arrived first, silently dropping one restriction — and because the
		// result would be a valid, shorter policy, nothing downstream would
		// notice.
		other := serviceStatement(newAllowSet([]string{"ec2"}, "set:other"), testGlobalNamespaces, PackOptions{})
		got := mergeStatements([]Statement{service, other})
		if len(got) != 2 {
			t.Fatalf("two service allowlists over different namespaces collapsed into %d statement(s); "+
				"one of the two restrictions was dropped:\n%s",
				len(got), describe("merged", &Merged{Statements: got}))
		}
	})

	t.Run("mergeStatements never sees one in the real pipeline", func(t *testing.T) {
		// The structural claim: Merge's output carries no NotAction, because the
		// field is set only by regionStatement and serviceStatement, which
		// renderable calls after the merge. A future edit that moved the allowlist
		// rendering into Merge would break here rather than in production.
		m := mustMerge(t, artifactWithSCP(t, "set", &artifact.SCP{
			Statements:       []artifact.SCPStatement{denyFragment("A", "iam:CreateUser")},
			RegionAllowlist:  []string{"us-east-1"},
			ServiceAllowlist: []string{"s3"},
		}))
		for _, st := range m.Statements {
			if st.isAllowlist() {
				t.Fatalf("Merge produced a NotAction statement (%q); the allowlists must stay as AllowSets "+
					"until the packer renders them, or two artifacts' allowlists would concatenate into a "+
					"deny-all instead of intersecting", st.Sid)
			}
		}
		if m.RegionAllowlist == nil || m.ServiceAllowlist == nil {
			t.Fatal("Merge dropped an allowlist entirely")
		}
	})
}

// TestTheGeneratorActuallyProducesMerges.
//
// The property suite's own honesty check. Every property in merge_property_test.go
// is satisfied vacuously by a merger that refuses to merge anything, so a
// generator that never produced a mergeable pair would leave the whole suite green
// while testing nothing. This asserts the generator hits both axes and the dedupe
// path, and it belongs here rather than there because it is a claim about the test,
// not about the code.
func TestTheGeneratorActuallyProducesMerges(t *testing.T) {
	// pairsPerCase and minPerPath together are the strength of the claim. A floor
	// of "at least one" would pass on a fluke and would have passed on the
	// vocabulary this suite started with, which produced a single axis-1 merge in a
	// hundred draws — technically nonzero, and nowhere near enough for rapid's
	// shrinking to have anything to work with on the axis that matters most.
	//
	// Each rapid case draws several pairs rather than one, because the number of
	// property cases is a flag the operator can lower (-rapid.checks) and this
	// test's meaning should not depend on it.
	//
	// pairsPerCase went from 24 to 112 at AUDIT-2, and the reason is the more useful
	// half of this test. Widening probeResources from two single-element lists to six
	// entries — the shapes H5's key collisions needed — necessarily DILUTES guard
	// collisions, because a guard must now agree on one resource list out of six rather
	// than one out of two. The intersection count fell from 60 to 21 against an
	// unchanged floor of 25, and this test said so.
	//
	// That is the trade stated plainly: reaching a new defect class cost collision
	// density on the axis that can widen a policy. Two ways out, and only one is
	// honest. Lowering minPerPath would make the number match the suite; drawing more
	// pairs restores the density the floor was set to demand. The floor is the claim,
	// so the sample size moves — and it moves to roughly four times the count that
	// clears the floor, not to the smallest number that clears it, because a margin of
	// a few merges is a test that fails on an unlucky seed rather than on a defect.
	const (
		pairsPerCase = 112
		minPerPath   = 25
	)

	// multiMemberResourceFloor is the second thing this test now measures, and it
	// exists because of how H5 escaped.
	//
	// TestUnionIsMonotone was green over every run while being structurally incapable
	// of reaching a CRITICAL widening: a key collision needs two members on some axis,
	// and every probeResources entry was a single-element list. The assertion was
	// sound; the input vocabulary could not produce the shape. Nothing about a passing
	// run said so, which is the dangerous failure — a starved generator is
	// indistinguishable from a correct implementation.
	//
	// So the generator's reach over its own input space is asserted, not assumed. If a
	// future edit trims probeResources back to single-element lists for tidiness, this
	// fails and names the reason, rather than the properties quietly going vacuous on
	// the axis that hid a critical finding.
	const multiMemberResourceFloor = 50

	var sawIntersection, sawGrouping, sawDedupe, total int
	var sawMultiMemberResource, sawEmptyResourceMember int
	rapid.Check(t, func(rt *rapid.T) {
		for i := 0; i < pairsPerCase; i++ {
			a := drawStatement(rt, fmt.Sprintf("a%d", i))
			// b may restate a, exactly as drawMerged lets a later statement restate
			// an earlier one — so this measures the generator the properties
			// actually use, not a simplified stand-in for it.
			b := drawRestatement(rt, fmt.Sprintf("b%d", i), []artifact.SCPStatement{a})
			sa := Statement{SCPStatement: a, Origins: []string{"a:0"}}
			sb := Statement{SCPStatement: b, Origins: []string{"b:0"}}
			total++

			// The input-space measurements, taken before the merge-path ones,
			// because they are claims about what was DRAWN rather than about what
			// the merger did with it.
			for _, st := range []Statement{sa, sb} {
				if len(st.Resource) > 1 {
					sawMultiMemberResource++
				}
				for _, r := range st.Resource {
					if r == "" {
						sawEmptyResourceMember++
					}
				}
			}

			if statementKey(sa) == statementKey(sb) {
				sawDedupe++
				continue
			}
			if guardKey(sa) != guardKey(sb) {
				// Different guards never interact, so the pair exercises nothing.
				continue
			}

			// An exemption intersection happened if some action both sides
			// constrain has an exemption on one side that the merge dropped.
			merged := mergeStatements([]Statement{sa, sb})
			if narrowedAnExemption(sa, sb, merged) {
				sawIntersection++
			}
			// A grouping happened if the merge produced fewer statements than the
			// two inputs' distinct action sets would need separately.
			if len(merged) < 2 {
				sawGrouping++
			}
		}
	})

	t.Logf("%d generated pairs: %d exemption intersections, %d groupings, %d dedupes", total,
		sawIntersection, sawGrouping, sawDedupe)
	t.Logf("input space over %d drawn statements: %d carried a multi-member resource list, %d carried "+
		"an empty resource member", total*2, sawMultiMemberResource, sawEmptyResourceMember)

	for _, c := range []struct {
		n    int
		what string
	}{
		{sawIntersection, "an exemption intersection (the merge that would WIDEN if it concatenated)"},
		{sawGrouping, "a grouping of two statements into one"},
		{sawDedupe, "the identical-statement dedupe path"},
	} {
		if c.n < minPerPath {
			t.Errorf("the generator produced only %d of %d pairs exercising %s, under the floor of %d; "+
				"the properties in merge_property_test.go pass vacuously for that case, so the vocabulary "+
				"in that file needs to collide more", c.n, total, c.what, minPerPath)
		}
	}

	// The input-space floors. A key collision needs two members on some axis, so a
	// vocabulary with no multi-member list cannot reach the class of defect H5 was —
	// and the properties would keep passing while unable to.
	if sawMultiMemberResource < multiMemberResourceFloor {
		t.Errorf("only %d of %d drawn statements carried a multi-member resource list, under the floor "+
			"of %d. A key-collision widening needs two members on some axis to be expressible at all "+
			"(AUDIT-2 H5), so with a vocabulary this thin TestUnionIsMonotone passes without being able "+
			"to reach that class of defect. Restore the multi-element entries in probeResources",
			sawMultiMemberResource, total*2, multiMemberResourceFloor)
	}
	if sawEmptyResourceMember < multiMemberResourceFloor {
		t.Errorf("only %d of %d drawn statements carried an empty resource member, under the floor of "+
			"%d. That member is the one H5 collision needing no control byte anywhere — {\"\"} keyed "+
			"identically to an absent resource — so it is the shape most likely to recur from ordinary "+
			"catalog data", sawEmptyResourceMember, total*2, multiMemberResourceFloor)
	}
}

// narrowedAnExemption reports whether the merge closed a hole that one input
// granted — the intersection actually doing something.
//
// The resource is read defensively: a statement with no resource denies on "*" once
// rendered (pack.go), and a statement whose only resource is "" denies nothing
// anywhere. Indexing Resource[0] unconditionally panicked on the first, which went
// unnoticed only because probeResources had no empty entry until AUDIT-2 added one.
func narrowedAnExemption(a, b Statement, merged []Statement) bool {
	for _, in := range []Statement{a, b} {
		for _, action := range in.Action {
			for _, e := range in.ExemptPrincipals {
				resource := "*"
				if len(in.Resource) > 0 {
					resource = in.Resource[0]
				}
				req := Request{
					Principal: e.Principal,
					Action:    action,
					Resource:  resource,
					Region:    "us-east-1",
					// The generated conditions gate on this key, and a request that
					// does not satisfy the guard is denied by nothing, so the
					// comparison below would be trivially equal.
					Conditions: map[string]string{"aws:SecureTransport": "false"},
				}
				if !Denies([]Statement{in}, req) && Denies(merged, req) {
					return true
				}
			}
		}
	}
	return false
}

func TestAllowlistsIntersectAcrossArtifacts(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want []string
		why  string
	}{
		{
			name: "overlap narrows to the shared regions",
			a:    []string{"us-east-1", "us-west-2"},
			b:    []string{"us-east-1"},
			want: []string{"us-east-1"},
			why:  "permitting fewer regions is stricter",
		},
		{
			name: "disjoint intersects to nothing, which is not nil",
			a:    []string{"us-east-1"},
			b:    []string{"eu-west-1"},
			want: []string{},
			why:  "an empty intersection is a conflict the packer must report, not an absent constraint",
		},
		{
			name: "identical lists are unchanged",
			a:    []string{"us-east-1", "us-west-2"},
			b:    []string{"us-west-2", "us-east-1"},
			want: []string{"us-east-1", "us-west-2"},
			why:  "order is not meaning",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := mustMerge(t,
				artifactWithSCP(t, "set-a", &artifact.SCP{
					Statements:      []artifact.SCPStatement{denyFragment("A", "iam:CreateUser")},
					RegionAllowlist: tc.a,
				}),
				artifactWithSCP(t, "set-b", &artifact.SCP{
					Statements:      []artifact.SCPStatement{denyFragment("B", "iam:CreateUser")},
					RegionAllowlist: tc.b,
				}),
			)
			if m.RegionAllowlist == nil {
				t.Fatalf("both artifacts constrained regions; the merge reports no constraint at all — %s", tc.why)
			}
			if !sameStrings(m.RegionAllowlist.Members, tc.want) || len(m.RegionAllowlist.Members) != len(tc.want) {
				t.Fatalf("got %v, want %v — %s", m.RegionAllowlist.Members, tc.want, tc.why)
			}
			if len(m.RegionAllowlist.Sources) != 2 {
				t.Errorf("both artifacts must appear in Sources so a conflict report can name them, got %v",
					m.RegionAllowlist.Sources)
			}
		})
	}
}

// TestAnUnconstrainedArtifactDoesNotConstrain.
//
// nil is the identity of the intersection, not the empty set. An artifact that
// says nothing about regions must not be read as permitting none — that reading
// would make adding a detective-only control set to a working configuration deny
// every call in the account.
func TestAnUnconstrainedArtifactDoesNotConstrain(t *testing.T) {
	constrained := artifactWithSCP(t, "set-a", &artifact.SCP{
		Statements:      []artifact.SCPStatement{denyFragment("A", "iam:CreateUser")},
		RegionAllowlist: []string{"us-east-1"},
	})
	silent := artifactWithSCP(t, "set-b", &artifact.SCP{
		Statements: []artifact.SCPStatement{denyFragment("B", "s3:PutBucketPolicy")},
	})

	for _, tc := range []struct {
		name string
		got  *Merged
	}{
		{"constrained first", mustMerge(t, constrained, silent)},
		{"silent first", mustMerge(t, silent, constrained)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.RegionAllowlist == nil {
				t.Fatal("the region constraint was lost")
			}
			if !sameStrings(tc.got.RegionAllowlist.Members, []string{"us-east-1"}) {
				t.Fatalf("got %v, want [us-east-1]", tc.got.RegionAllowlist.Members)
			}
		})
	}

	if got := mustMerge(t, silent, silent); got.RegionAllowlist != nil {
		t.Errorf("two artifacts that say nothing about regions must leave the allowlist nil, got %v",
			got.RegionAllowlist.Members)
	}
}

// TestMergeIgnoresControlsWithoutAnSCP is the honest-empty case: a control set
// that is entirely detective produces no statements, which the packer must handle
// rather than error on.
func TestMergeIgnoresControlsWithoutAnSCP(t *testing.T) {
	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta:          artifact.Meta{ID: "detective-only"},
		Controls: artifact.Controls{
			{ID: "c-1", Title: "Monitored only", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule}},
		},
	}
	m := mustMerge(t, a)
	if len(m.Statements) != 0 {
		t.Fatalf("expected no statements, got %d", len(m.Statements))
	}
	if m.RegionAllowlist != nil || m.ServiceAllowlist != nil {
		t.Error("a control set with no SCP must not constrain the allowlists")
	}
}

func TestMergeToleratesNilArtifacts(t *testing.T) {
	// Not defensive noise: the vend path builds this list from optional sources —
	// a catalog, a campus baseline, an override — and a nil for "not supplied" is
	// the natural shape. A panic here would surface as a crash mid-vend.
	m, err := Merge(nil, nil)
	if err != nil || m == nil || len(m.Statements) != 0 {
		t.Fatalf("Merge(nil, nil) must return an empty result and no error, not nil and not a panic (err=%v)", err)
	}
	c, cerr := Combine(nil, nil)
	if cerr != nil || c == nil {
		t.Fatalf("Combine(nil, nil) must return an empty result and no error (err=%v)", cerr)
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func denyFragment(sid, action string) artifact.SCPStatement {
	return artifact.SCPStatement{
		Sid:      sid,
		Effect:   "Deny",
		Action:   []string{action},
		Resource: []string{"*"},
	}
}

// artifactWithSCP builds a valid artifact carrying one control with the given SCP.
//
// It runs Validate, so a fixture that could not exist as a real catalog fails the
// test that uses it rather than silently exercising a shape the loader would
// reject. A merge test over an impossible input proves nothing.
func artifactWithSCP(t *testing.T, id string, scp *artifact.SCP) *artifact.Artifact {
	t.Helper()
	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{
			ID:         id,
			Title:      "Test control set " + id,
			CompiledAt: "2026-01-01T00:00:00Z",
			Sources: artifact.Sources{{
				Catalog: "test",
				SHA256:  strings.Repeat("0", 64),
			}},
		},
		Controls: artifact.Controls{{
			ID:          "c-1",
			Title:       "Preventive control",
			Enforcement: []artifact.EnforcementClass{artifact.EnforcementSCP},
			SCP:         scp,
		}},
	}
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("fixture %s: %v", id, err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("fixture %s is not a valid artifact, so a test using it proves nothing: %v", id, err)
	}
	return a
}
