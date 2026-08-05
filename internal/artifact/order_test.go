// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Property tests for parameter resolution (DESIGN §9).
//
// Four properties, stated over generated bindings rather than examples: a
// non-monotone order would silently loosen a control at vend time, and the
// failure mode is a specific pair of values nobody thought to write down.
//
//	idempotence   A ∪ A = A
//	commutativity A ∪ B = B ∪ A
//	associativity (A ∪ B) ∪ C = A ∪ (B ∪ C)
//	monotonicity  if either A or B forbids a behavior, A ∪ B forbids it
//
// Monotonicity is the load-bearing one; the other three are what make the
// artifact-level union in Phase 4 a well-defined meet on a semilattice, so that
// compiling the same control sets in a different order cannot produce a
// different artifact.

// numericValues keeps generated values inside a range where float64 comparison
// and decimal round-tripping are both exact, so a failure means the order is
// wrong rather than that the test hit a representation edge.
func numericValues(t *rapid.T, label string) string {
	return strconv.Itoa(rapid.IntRange(0, 4096).Draw(t, label))
}

func setValue(t *rapid.T, label string) string {
	members := rapid.SliceOfNDistinct(
		rapid.SampledFrom([]string{"20", "21", "22", "80", "443", "3306", "3389", "kms:Decrypt", "kms:ReEncryptFrom"}),
		1, 6,
		func(s string) string { return s },
	).Draw(t, label)
	return strings.Join(members, ",")
}

// drawBinding generates a binding for the given order, already canonical, as a
// compiled artifact's bindings always are.
func drawBinding(t *rapid.T, order ParamOrder, label string) RuleParameter {
	p := RuleParameter{Order: order}
	switch order {
	case OrderMin, OrderMax:
		p.Value = numericValues(t, label)
	case OrderExact:
		p.Value = rapid.SampledFrom([]string{"true", "false", "90", "14"}).Draw(t, label)
	case OrderSetUnion, OrderSetIntersect:
		p.Value = setValue(t, label)
	}
	p.canonicalize()
	return p
}

// candidates are the behaviors monotonicity is checked against: every set member
// that appears in a generated value, plus numbers spanning the numeric range.
var candidates = []string{
	"0", "1", "13", "14", "15", "89", "90", "91", "4096",
	"20", "21", "22", "80", "443", "3306", "3389",
	"kms:Decrypt", "kms:ReEncryptFrom", "kms:Encrypt",
	"true", "false",
}

func TestResolveIsIdempotent(t *testing.T) {
	for _, order := range AllParamOrders {
		t.Run(string(order), func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := drawBinding(rt, order, "a")
				got, err := a.Resolve(a, "rule", "param")
				if err != nil {
					rt.Fatalf("A ∪ A must never conflict, but %+v did: %v", a, err)
				}
				if got != a {
					rt.Fatalf("A ∪ A = %+v, want %+v", got, a)
				}
			})
		})
	}
}

func TestResolveIsCommutative(t *testing.T) {
	for _, order := range AllParamOrders {
		t.Run(string(order), func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := drawBinding(rt, order, "a")
				b := drawBinding(rt, order, "b")

				ab, abErr := a.Resolve(b, "rule", "param")
				ba, baErr := b.Resolve(a, "rule", "param")

				// Conflicting must be symmetric too: whether a pair needs an
				// override cannot depend on the order the sets were listed in.
				if (abErr == nil) != (baErr == nil) {
					rt.Fatalf("A ∪ B and B ∪ A disagree on whether the pair conflicts: %v vs %v", abErr, baErr)
				}
				if abErr != nil {
					return
				}
				if ab != ba {
					rt.Fatalf("A ∪ B = %+v but B ∪ A = %+v", ab, ba)
				}
			})
		})
	}
}

func TestResolveIsAssociative(t *testing.T) {
	for _, order := range AllParamOrders {
		t.Run(string(order), func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := drawBinding(rt, order, "a")
				b := drawBinding(rt, order, "b")
				c := drawBinding(rt, order, "c")

				ab, err1 := a.Resolve(b, "rule", "param")
				bc, err2 := b.Resolve(c, "rule", "param")
				if err1 != nil || err2 != nil {
					return
				}
				left, lerr := ab.Resolve(c, "rule", "param")
				right, rerr := a.Resolve(bc, "rule", "param")
				if (lerr == nil) != (rerr == nil) {
					rt.Fatalf("(A ∪ B) ∪ C and A ∪ (B ∪ C) disagree on conflict: %v vs %v", lerr, rerr)
				}
				if lerr != nil {
					return
				}
				if left != right {
					rt.Fatalf("(A ∪ B) ∪ C = %+v but A ∪ (B ∪ C) = %+v", left, right)
				}
			})
		})
	}
}

// TestResolveIsMonotone is the property that matters: the resolved binding must
// never permit a behavior either input forbade.
//
// This is what "union of controls = intersection of permitted behavior"
// (DESIGN §9) means operationally. A violation is a control silently loosened by
// compiling two catalogs together — the worst failure this tool can have.
func TestResolveIsMonotone(t *testing.T) {
	for _, order := range AllParamOrders {
		t.Run(string(order), func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := drawBinding(rt, order, "a")
				b := drawBinding(rt, order, "b")

				got, err := a.Resolve(b, "rule", "param")
				if err != nil {
					return // A conflict permits nothing; it stops the compile.
				}
				for _, cand := range candidates {
					permitted, meaningful := got.Permits(cand)
					if !meaningful || !permitted {
						continue
					}
					pa, okA := a.Permits(cand)
					pb, okB := b.Permits(cand)
					if okA && !pa {
						rt.Fatalf("resolved %+v permits %q, but input A %+v forbids it", got, cand, a)
					}
					if okB && !pb {
						rt.Fatalf("resolved %+v permits %q, but input B %+v forbids it", got, cand, b)
					}
				}
			})
		})
	}
}

// TestResolveKeepsEveryForbiddenBehaviorForbidden is monotonicity from the other
// side, and it is the direction a too-clever "resolution" would break: it is
// trivially easy to be monotone by forbidding everything.
//
// Together with the above, this pins resolution to the *greatest* value no
// stricter than either input, rather than to something arbitrarily strict.
func TestResolveIsNoStricterThanNecessary(t *testing.T) {
	for _, order := range AllParamOrders {
		t.Run(string(order), func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				a := drawBinding(rt, order, "a")
				b := drawBinding(rt, order, "b")

				got, err := a.Resolve(b, "rule", "param")
				if err != nil {
					return
				}
				for _, cand := range candidates {
					pa, okA := a.Permits(cand)
					pb, okB := b.Permits(cand)
					if !okA || !okB || !pa || !pb {
						continue
					}
					// Both inputs permit it, so the meet must too.
					permitted, meaningful := got.Permits(cand)
					if meaningful && !permitted {
						rt.Fatalf("resolved %+v forbids %q, which both inputs %+v and %+v permit", got, cand, a, b)
					}
				}
			})
		})
	}
}

// TestResolveTableCases pins the concrete behavior a reader will reason about,
// including every way resolution refuses to guess.
func TestResolveTableCases(t *testing.T) {
	for _, tc := range []struct {
		name      string
		a, b      RuleParameter
		want      string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "min takes the lower ceiling",
			a:    RuleParameter{Value: "90", Order: OrderMin},
			b:    RuleParameter{Value: "30", Order: OrderMin},
			want: "30",
		},
		{
			name: "max takes the higher floor",
			a:    RuleParameter{Value: "14", Order: OrderMax},
			b:    RuleParameter{Value: "20", Order: OrderMax},
			want: "20",
		},
		{
			name: "exact agrees",
			a:    RuleParameter{Value: "true", Order: OrderExact},
			b:    RuleParameter{Value: "true", Order: OrderExact},
			want: "true",
		},
		{
			name:      "exact disagrees",
			a:         RuleParameter{Value: "true", Order: OrderExact},
			b:         RuleParameter{Value: "false", Order: OrderExact},
			wantErr:   true,
			errSubstr: "no stricter direction",
		},
		{
			name: "set-union prohibits both sets",
			a:    RuleParameter{Value: "20,21", Order: OrderSetUnion},
			b:    RuleParameter{Value: "3389", Order: OrderSetUnion},
			want: "20,21,3389",
		},
		{
			name: "set-intersect permits only the overlap",
			a:    RuleParameter{Value: "443,22,80", Order: OrderSetIntersect},
			b:    RuleParameter{Value: "443,22", Order: OrderSetIntersect},
			want: "22,443",
		},
		{
			name:      "set-intersect with disjoint sets is a conflict",
			a:         RuleParameter{Value: "443", Order: OrderSetIntersect},
			b:         RuleParameter{Value: "22", Order: OrderSetIntersect},
			wantErr:   true,
			errSubstr: "disjoint",
		},
		{
			name:      "different orders is a conflict",
			a:         RuleParameter{Value: "90", Order: OrderMin},
			b:         RuleParameter{Value: "90", Order: OrderMax},
			wantErr:   true,
			errSubstr: "different orders",
		},
		{
			name:      "numeric order over a non-numeric value is a conflict",
			a:         RuleParameter{Value: "true", Order: OrderMin},
			b:         RuleParameter{Value: "false", Order: OrderMin},
			wantErr:   true,
			errSubstr: "not a number",
		},
		{
			name:      "different separators is a conflict",
			a:         RuleParameter{Value: "20,21", Order: OrderSetUnion},
			b:         RuleParameter{Value: "3389", Order: OrderSetUnion, SetSeparator: ";"},
			wantErr:   true,
			errSubstr: "different separators",
		},
		{
			name:      "invalid order is a conflict, not a default",
			a:         RuleParameter{Value: "1", Order: ParamOrder("first-wins")},
			b:         RuleParameter{Value: "2", Order: ParamOrder("first-wins")},
			wantErr:   true,
			errSubstr: "not one of",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.a.Resolve(tc.b, "restricted-common-ports", "blockedPort1")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Resolve = %+v, want a conflict", got)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("conflict message %q does not mention %q", err.Error(), tc.errSubstr)
				}
				// Every conflict must tell the operator what to do next
				// (CLAUDE.md rule 7).
				if !strings.Contains(err.Error(), "override") {
					t.Errorf("conflict message %q does not name the remediation", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got.Value != tc.want {
				t.Errorf("Resolve value = %q, want %q", got.Value, tc.want)
			}
		})
	}
}

// TestPermitsReadsEachOrderCorrectly pins the behavioral reading the
// monotonicity properties are stated against. If Permits is wrong, those
// properties pass while meaning nothing, so it is checked directly.
func TestPermitsReadsEachOrderCorrectly(t *testing.T) {
	for _, tc := range []struct {
		name          string
		p             RuleParameter
		candidate     string
		wantPermitted bool
		wantMeaning   bool
	}{
		{"min permits at the ceiling", RuleParameter{Value: "90", Order: OrderMin}, "90", true, true},
		{"min permits below", RuleParameter{Value: "90", Order: OrderMin}, "30", true, true},
		{"min forbids above", RuleParameter{Value: "90", Order: OrderMin}, "120", false, true},
		{"max permits at the floor", RuleParameter{Value: "14", Order: OrderMax}, "14", true, true},
		{"max forbids below", RuleParameter{Value: "14", Order: OrderMax}, "8", false, true},
		{"max permits above", RuleParameter{Value: "14", Order: OrderMax}, "20", true, true},
		{"exact permits itself", RuleParameter{Value: "true", Order: OrderExact}, "true", true, true},
		{"exact forbids others", RuleParameter{Value: "true", Order: OrderExact}, "false", false, true},
		{"set-union forbids a member", RuleParameter{Value: "20,21", Order: OrderSetUnion}, "21", false, true},
		{"set-union permits a non-member", RuleParameter{Value: "20,21", Order: OrderSetUnion}, "443", true, true},
		{"set-intersect permits a member", RuleParameter{Value: "443", Order: OrderSetIntersect}, "443", true, true},
		{"set-intersect forbids a non-member", RuleParameter{Value: "443", Order: OrderSetIntersect}, "22", false, true},
		{"min over a non-number is meaningless", RuleParameter{Value: "90", Order: OrderMin}, "true", false, false},
		{"an unknown order is meaningless", RuleParameter{Value: "x", Order: ParamOrder("bogus")}, "x", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			permitted, meaningful := tc.p.Permits(tc.candidate)
			if meaningful != tc.wantMeaning {
				t.Fatalf("meaningful = %v, want %v", meaningful, tc.wantMeaning)
			}
			if meaningful && permitted != tc.wantPermitted {
				t.Errorf("permits %q = %v, want %v", tc.candidate, permitted, tc.wantPermitted)
			}
		})
	}
}

// TestMembersNormalizesSets checks the canonical form set orders rely on: two
// spellings of one set must produce one content hash, or the artifact hash in an
// account tag depends on whitespace.
func TestMembersNormalizesSets(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    RuleParameter
		want []string
	}{
		{"trims and sorts", RuleParameter{Value: " 21 , 20 ", Order: OrderSetUnion}, []string{"20", "21"}},
		{"dedupes", RuleParameter{Value: "20,20,21", Order: OrderSetUnion}, []string{"20", "21"}},
		{"drops empties", RuleParameter{Value: "20,,21,", Order: OrderSetUnion}, []string{"20", "21"}},
		{
			"honors an explicit separator",
			RuleParameter{Value: "kms:Decrypt;kms:Encrypt", Order: OrderSetUnion, SetSeparator: ";"},
			[]string{"kms:Decrypt", "kms:Encrypt"},
		},
		{"a scalar has no members", RuleParameter{Value: "90", Order: OrderMin}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.p.Members()
			if len(got) != len(tc.want) {
				t.Fatalf("Members = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Members = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
