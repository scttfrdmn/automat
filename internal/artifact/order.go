// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"fmt"
	"strconv"
	"strings"
)

// Parameter resolution: the single-parameter half of union semantics
// (DESIGN §9).
//
// Resolve answers one question — when two control sets bind the same Config rule
// parameter, what value satisfies both? — and it is the only place the meaning of
// a ParamOrder lives. The artifact-level union (rule set dedupe, crosswalk
// dedupe, SCP packing, conflict reports) is Phase 4 and builds on this.
//
// The governing law is monotonicity: the resolved value must never permit
// behavior either input forbade. Every order below is a meet on the parameter's
// own value space, which is what makes the artifact-level operation a meet on a
// semilattice — idempotent, commutative, and associative. order_test.go states
// those four properties as property tests, because a subtly non-monotone order
// would silently loosen a control at vend time and no example-based test is
// likely to catch it.

// ParamConflict reports two bindings of one parameter that cannot be reconciled
// without a human deciding which is meant.
//
// It is an error value carrying remediation text rather than a bare sentinel:
// the operator's next action is to write an override, and the message has to say
// so (CLAUDE.md rule 7).
type ParamConflict struct {
	// Parameter is the rule parameter name, e.g. "MinimumPasswordLength".
	Parameter string
	// Rule is the Config rule the parameter belongs to, if known.
	Rule string
	// A and B are the two conflicting values.
	A, B string
	// Order is the declared order that failed to resolve them.
	Order ParamOrder
	// Reason says what about the pair could not be resolved.
	Reason string
}

// Error renders the conflict with every catalog-supplied value quoted. Rule and
// parameter names come from artifact files, which are attacker-controlled in the
// threat model, and a conflict report is read as a report — an unescaped newline
// in a rule name could forge a line of it. AUDIT-0 finding M1.
func (c *ParamConflict) Error() string {
	where := safe(c.Parameter)
	if c.Rule != "" {
		where = safe(c.Rule) + " parameter " + safe(c.Parameter)
	}
	return fmt.Sprintf("%s binds conflicting values %s and %s under order %s: %s. "+
		"Resolve it explicitly in an override file naming %s and the value you intend; "+
		"union must never guess which is stricter (DESIGN §9)",
		where, safe(c.A), safe(c.B), safe(string(c.Order)), c.Reason, safe(c.Parameter))
}

// Resolve returns the binding that satisfies both p and other.
//
// Both bindings must declare the same order — the order is a property of what
// the parameter means, so two catalogs disagreeing about it is a conflict in
// itself, not something to arbitrate.
//
// rule and param name the binding for the error message only.
func (p RuleParameter) Resolve(other RuleParameter, rule, param string) (RuleParameter, error) {
	conflict := func(reason string) (RuleParameter, error) {
		return RuleParameter{}, &ParamConflict{
			Parameter: param, Rule: rule, A: p.Value, B: other.Value, Order: p.Order, Reason: reason,
		}
	}

	if p.Order != other.Order {
		return RuleParameter{}, &ParamConflict{
			Parameter: param, Rule: rule, A: p.Value, B: other.Value, Order: p.Order,
			Reason: fmt.Sprintf("the two bindings declare different orders (%s and %s), so there is no "+
				"agreed notion of which direction is stricter", p.Order, other.Order),
		}
	}
	if !p.Order.valid() {
		return RuleParameter{}, &ParamConflict{
			Parameter: param, Rule: rule, A: p.Value, B: other.Value, Order: p.Order,
			Reason: "the declared order is not one of " + orderList(),
		}
	}

	switch p.Order {
	case OrderExact:
		if p.Value != other.Value {
			return conflict("the order is exact, which asserts there is no stricter direction")
		}
		return p, nil

	case OrderMin, OrderMax:
		if p.Value == other.Value {
			return p, nil
		}
		a, aerr := strconv.ParseFloat(p.Value, 64)
		b, berr := strconv.ParseFloat(other.Value, 64)
		if aerr != nil || berr != nil {
			// A non-numeric value under a numeric order is a source error, not
			// something to resolve by string comparison: "true" < "false" is
			// meaningless and picking either could loosen the control.
			return conflict(fmt.Sprintf("order %s compares values numerically, and at least one value is "+
				"not a number", p.Order))
		}
		if (p.Order == OrderMin) == (a < b) {
			return p, nil
		}
		return other, nil

	case OrderSetUnion, OrderSetIntersect:
		if p.Separator() != other.Separator() {
			return conflict(fmt.Sprintf("the two bindings split members on different separators (%q and %q), "+
				"so their members cannot be compared", p.Separator(), other.Separator()))
		}
		members := setResolve(p.Order, p.Members(), other.Members())
		if len(members) == 0 && p.Order == OrderSetIntersect {
			// An empty allowlist is not "permit nothing" to a Config rule; it is
			// a parameter the rule will reject. Two catalogs with disjoint
			// allowlists genuinely disagree, so say so.
			return conflict("the order is set-intersect and the two permitted sets are disjoint, leaving " +
				"no permitted member")
		}
		out := p
		out.Value = strings.Join(members, p.Separator())
		return out, nil
	}

	// Unreachable: valid() above admits only the cases handled.
	return conflict("unhandled order")
}

// setResolve is the member-level meet for the two set orders.
//
// Both inputs must already be canonical (sorted, deduped), as Members returns
// them, so the output is canonical too — which is what keeps the operation
// associative rather than merely order-insensitive.
func setResolve(order ParamOrder, a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, m := range b {
		in[m] = true
	}
	if order == OrderSetIntersect {
		// Intersect: only members both inputs permit survive. Permitting fewer
		// is stricter, so this is the monotone direction.
		out := make([]string, 0, min(len(a), len(b)))
		for _, m := range a {
			if in[m] {
				out = append(out, m)
			}
		}
		return sortedUnique(out)
	}
	// Union: every member either input prohibits survives. Prohibiting more is
	// stricter, so this is the monotone direction.
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return sortedUnique(out)
}

// Permits reports whether the binding permits the given candidate — the
// behavioral reading of a parameter value, and the predicate monotonicity is
// stated against.
//
// The candidate is a member for set orders and a numeric value for min/max. The
// second return is false when the candidate is not meaningful for the order (a
// non-numeric candidate under min, say), so a property test can skip rather
// than assert nonsense.
//
// The reading of each order:
//
//   - min: the value is a ceiling (max key age 90), so a candidate at or below
//     it is permitted.
//   - max: the value is a floor (min password length 14), so a candidate at or
//     above it is permitted.
//   - exact: only the value itself.
//   - set-union: the members are prohibited, so a candidate is permitted iff it
//     is not a member.
//   - set-intersect: the members are permitted, so a candidate is permitted iff
//     it is a member.
func (p RuleParameter) Permits(candidate string) (permitted, meaningful bool) {
	switch p.Order {
	case OrderExact:
		return candidate == p.Value, true

	case OrderMin, OrderMax:
		c, cerr := strconv.ParseFloat(candidate, 64)
		v, verr := strconv.ParseFloat(p.Value, 64)
		if cerr != nil || verr != nil {
			return false, false
		}
		if p.Order == OrderMin {
			return c <= v, true
		}
		return c >= v, true

	case OrderSetUnion, OrderSetIntersect:
		found := false
		for _, m := range p.Members() {
			if m == candidate {
				found = true
				break
			}
		}
		if p.Order == OrderSetUnion {
			return !found, true
		}
		return found, true
	}
	return false, false
}
