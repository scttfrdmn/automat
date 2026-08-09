// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Property tests for the Config-rule half of union (DESIGN §9), the
// detective-side counterpart to merge_property_test.go's SCP properties:
//
//	idempotence   A ∪ A = A
//	commutativity A ∪ B = B ∪ A
//	associativity (A ∪ B) ∪ C = A ∪ (B ∪ C)
//
// Monotonicity has no separate property test here: RuleParameter.Resolve's
// own order_test.go already holds monotonicity per-parameter
// (TestResolveIsMonotone), and configrules.go adds no behavior on top of
// Resolve beyond dedupe-by-identifier and re-slotting — dedupe cannot widen
// a parameter's value (it either keeps one side's value untouched or
// resolves via Resolve), and re-slotting is a reshaping of an already-set-
// union value into five parameters, not a second union.
//
// # Why the generator draws exact-order parameters only
//
// A generator drawing min/max/set-union parameters at random would make
// combineTwo's error path (a real conflict) the COMMON case rather than the
// rare one it needs to be for idempotence/commutativity/associativity to be
// checkable at all — those three properties are about what happens when
// resolution SUCCEEDS, and TestConfigRuleConflictIsAConflictReport already
// covers the failure path directly. So this generator draws from a small,
// fixed vocabulary of (rule, parameter, value) triples with the exact order,
// the same "small overlapping vocabulary so collisions are the common case"
// reasoning merge_property_test.go's own comment gives for its statement
// generator — except here the goal is the opposite of a collision: two
// artifacts binding the SAME parameter to the SAME value, which is what
// exact-order resolution can always satisfy.
var (
	probeConfigRuleIDs = []string{"IAM_PASSWORD_POLICY", "RESTRICTED_INCOMING_TRAFFIC"}
	probeConfigParams  = map[string][]string{
		"IAM_PASSWORD_POLICY":         {"RequireSymbols", "RequireNumbers"},
		"RESTRICTED_INCOMING_TRAFFIC": {"blockedPort1"},
	}
	probeConfigValues = []string{"true", "false"}
)

func drawConfigRules(t *rapid.T, label string) map[string]*MergedConfigRule {
	n := rapid.IntRange(0, 2).Draw(t, label+".n")
	if n == 0 {
		return nil
	}
	out := map[string]*MergedConfigRule{}
	for i := 0; i < n; i++ {
		id := rapid.SampledFrom(probeConfigRuleIDs).Draw(t, fmt.Sprintf("%s.rule%d.id", label, i))
		params := map[string]artifact.RuleParameter{}
		for _, name := range probeConfigParams[id] {
			if !rapid.Bool().Draw(t, fmt.Sprintf("%s.rule%d.%s.has", label, i, name)) {
				continue
			}
			val := rapid.SampledFrom(probeConfigValues).Draw(t, fmt.Sprintf("%s.rule%d.%s.val", label, i, name))
			params[name] = artifact.RuleParameter{Value: val, Order: artifact.OrderExact}
		}
		origin := fmt.Sprintf("%s:control-%d", label, i)
		out[id] = &MergedConfigRule{
			Identifier: id, Parameters: params, Origins: []string{origin},
		}
	}
	return out
}

// combineConfig combines just the ConfigRules half of two hand-built Merged
// values, skipping the rapid draw entirely on a genuine conflict — the
// exact-order generator above makes a conflict rare (both sides must bind
// the same parameter to DIFFERENT values), not impossible, and a property
// about the success path has nothing to assert when resolution legitimately
// refuses.
func combineConfig(rt *rapid.T, a, b map[string]*MergedConfigRule) (map[string]*MergedConfigRule, bool) {
	ma, mb := &Merged{ConfigRules: a}, &Merged{ConfigRules: b}
	out, cr := combineConfigRules(ma, mb, nil)
	if cr != nil {
		rt.Skip("generated a genuine parameter conflict: " + cr.Error())
		return nil, false
	}
	return out, true
}

// configRulesKey is a canonical, order-independent identity for a
// ConfigRules map, for comparing two merge results the way mergedKey
// compares two statement sets.
func configRulesKey(rules map[string]*MergedConfigRule) string {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var sb strings.Builder
	for _, id := range ids {
		r := rules[id]
		sb.WriteString(id)
		sb.WriteString("|")
		names := make([]string, 0, len(r.Parameters))
		for name := range r.Parameters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&sb, "%s=%s;", name, r.Parameters[name].Value)
		}
		sb.WriteString("||")
	}
	return sb.String()
}

func TestConfigRuleUnionIsIdempotent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawConfigRules(rt, "a")
		u, ok := combineConfig(rt, a, a)
		if !ok {
			return
		}
		if got, want := configRulesKey(u), configRulesKey(a); got != want {
			rt.Fatalf("A ∪ A ≠ A.\nA:     %s\nA ∪ A: %s", want, got)
		}
	})
}

func TestConfigRuleUnionIsCommutative(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawConfigRules(rt, "a")
		b := drawConfigRules(rt, "b")
		ab, ok1 := combineConfig(rt, a, b)
		ba, ok2 := combineConfig(rt, b, a)
		if !ok1 || !ok2 {
			return
		}
		if configRulesKey(ab) != configRulesKey(ba) {
			rt.Fatalf("A ∪ B ≠ B ∪ A.\nA ∪ B: %s\nB ∪ A: %s", configRulesKey(ab), configRulesKey(ba))
		}
	})
}

func TestConfigRuleUnionIsAssociative(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawConfigRules(rt, "a")
		b := drawConfigRules(rt, "b")
		c := drawConfigRules(rt, "c")

		ab, ok1 := combineConfig(rt, a, b)
		if !ok1 {
			return
		}
		left, ok2 := combineConfig(rt, ab, c)
		bc, ok3 := combineConfig(rt, b, c)
		if !ok2 || !ok3 {
			return
		}
		right, ok4 := combineConfig(rt, a, bc)
		if !ok4 {
			return
		}
		if configRulesKey(left) != configRulesKey(right) {
			rt.Fatalf("(A ∪ B) ∪ C ≠ A ∪ (B ∪ C).\nleft:  %s\nright: %s",
				configRulesKey(left), configRulesKey(right))
		}
	})
}
