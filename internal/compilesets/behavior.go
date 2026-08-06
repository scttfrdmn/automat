// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"sort"
	"strings"
)

// The behavioral model: what a merged statement set actually DENIES.
//
// This exists because "can any merge widen permissions" is not a question about
// documents. Two policies can differ in every byte and deny the same behavior;
// two policies can differ in one character and differ in what an account may do.
// Comparing rendered output would test the packer's formatting; comparing denied
// behavior tests the claim DESIGN §9 makes.
//
// So: a Request is a point in the space of things a principal might attempt, and
// Denies answers whether the statement set forbids it. Monotonicity is then
// stateable as an implication over that predicate — if any input denied a
// request, the merge denies it too — and it is checkable by a property test that
// draws requests it never saw during development.
//
// # Why a model and not the real IAM evaluator
//
// This is a MODEL of SCP evaluation, not a reimplementation, and it is
// deliberately narrower than IAM in the strict direction. It handles the shapes
// automat's catalogs can express: Deny with actions or NotAction, resource and
// action wildcards, the condition operators the catalogs use, and the ArnNotLike
// exemption. It does not model policy variables, ForAnyValue/ForAllValues set
// operators, or IAM's full condition-key vocabulary.
//
// The narrowness is safe in one direction only, so it is worth naming which.
// unknownOperator returns "this statement does not deny the request", meaning the
// model UNDER-reports denial. For monotonicity — "everything an input denied, the
// merge denies" — under-reporting on the input side weakens the hypothesis and
// under-reporting on the output side strengthens the conclusion, so a real
// widening cannot be hidden by an unmodeled operator: the merge would have to
// under-report a denial the input over-reported, and the model is the same code
// on both sides. What the narrowness costs is coverage, not soundness: a
// statement whose operator the model does not understand contributes nothing to
// the property, which is why unknownOperators is exported and asserted empty over
// the shipped catalogs.

// Request is one attempted call: who, what, where.
//
// Region is separate from Conditions even though IAM sees it as
// aws:RequestedRegion, because the region allowlist is the one control automat
// generates itself and a property test needs to vary the region without knowing
// the key name.
type Request struct {
	Principal  string
	Action     string
	Resource   string
	Region     string
	Conditions map[string]string
}

// conditionValue returns the value the request presents for an IAM condition key.
func (r Request) conditionValue(key string) (string, bool) {
	switch key {
	case "aws:RequestedRegion":
		if r.Region == "" {
			return "", false
		}
		return r.Region, true
	case "aws:PrincipalArn":
		if r.Principal == "" {
			return "", false
		}
		return r.Principal, true
	}
	v, ok := r.Conditions[key]
	return v, ok
}

// Denies reports whether any statement in the set denies the request.
//
// Deny-only, so this is an OR over the statements: SCPs have no Allow that can
// rescue a Deny, which is exactly why concatenation is monotone and why this
// function is a disjunction rather than an evaluation order.
func Denies(statements []Statement, r Request) bool {
	for _, st := range statements {
		if st.denies(r) {
			return true
		}
	}
	return false
}

// denies reports whether one statement denies the request.
func (s Statement) denies(r Request) bool {
	if s.Effect != "Deny" {
		// Not reachable through a validated artifact — Deny is the only permitted
		// effect — but the model must not silently treat an Allow as a Deny if one
		// ever appears.
		return false
	}

	if s.isAllowlist() {
		// NotAction: the statement covers every action EXCEPT those listed.
		if matchesAny(s.NotAction, r.Action) {
			return false
		}
	} else if !matchesAny(s.Action, r.Action) {
		return false
	}

	if len(s.Resource) > 0 && !matchesAny(s.Resource, r.Resource) {
		return false
	}

	// The exemption list. Checked before the conditions rather than folded into
	// them, because Denies is called on merged statements whose exemptions have
	// not been rendered into a condition yet — the model has to give the same
	// answer before and after Pack, or the property tests would be comparing two
	// different things.
	for _, e := range s.ExemptPrincipals {
		if e.Principal == r.Principal {
			return false
		}
	}

	for op, keys := range s.Condition {
		for key, values := range keys {
			if !conditionMatches(op, key, values, r) {
				return false
			}
		}
	}
	return true
}

// conditionMatches evaluates one condition key against the request.
//
// An unmodeled operator returns false — the statement does not deny — which is
// the under-reporting direction the package comment justifies. UnknownOperators
// reports which operators a statement set uses that this does not model, so a
// test can assert the shipped catalogs stay inside the modeled set.
func conditionMatches(op, key string, values []string, r Request) bool {
	value, present := r.conditionValue(key)

	// The IfExists suffix: the condition passes when the key is absent.
	base := strings.TrimSuffix(op, "IfExists")
	if base != op && !present {
		return true
	}
	if !present {
		// A condition on a key the request does not carry does not match, which
		// means the statement does not deny. This is IAM's behavior for the
		// non-IfExists operators.
		return false
	}

	switch base {
	case "StringEquals":
		return contains(values, value)
	case "StringNotEquals":
		return !contains(values, value)
	case "StringLike":
		return matchesAny(values, value)
	case "StringNotLike":
		return !matchesAny(values, value)
	case "ArnEquals", "ArnLike":
		return matchesAny(values, value)
	case "ArnNotEquals", "ArnNotLike":
		return !matchesAny(values, value)
	case "Bool":
		return contains(values, value)
	}
	return false
}

// negativeOperators are the modeled operators whose match means "does NOT match".
//
// Here rather than in pack.go because this is where the operator vocabulary is
// modeled, and the packer's conflict check has to be about the same set the model
// evaluates or the two disagree about what a statement means. AUDIT-2 found the
// packer checking a single literal against a set of six.
var negativeOperators = []string{
	"StringNotEquals", "StringNotLike",
	"ArnNotEquals", "ArnNotLike",
}

// isNegativeOperator reports whether op is a modeled negative operator, ignoring an
// IfExists suffix.
//
// The suffix is stripped rather than rejected: ArnNotLikeIfExists is the same
// operator with an absent-key rule, so a statement carrying it constrains the key in
// exactly the way a conflict check cares about. conditionMatches trims it for the
// same reason.
func isNegativeOperator(op string) bool {
	return contains(negativeOperators, strings.TrimSuffix(op, "IfExists"))
}

// UnknownOperators returns the condition operators in the statement set that the
// behavioral model does not evaluate, sorted.
//
// Exported and asserted empty over the shipped catalogs
// (TestTheModelUnderstandsEveryOperatorTheCatalogsUse), because the model's
// under-reporting is only harmless when it is measured. An operator the model
// silently skips is a statement that contributes nothing to the monotonicity
// property — the test would pass while checking less than it claims, which is the
// failure mode a property suite is most prone to.
func UnknownOperators(statements []Statement) []string {
	var out []string
	for _, st := range statements {
		for op := range st.Condition {
			switch strings.TrimSuffix(op, "IfExists") {
			case "StringEquals", "StringNotEquals", "StringLike", "StringNotLike",
				"ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike", "Bool":
			default:
				out = append(out, op)
			}
		}
	}
	return sortedUnique(out)
}

// matchesAny reports whether the value matches any pattern, with IAM's `*` and
// `?` wildcards.
func matchesAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if wildcardMatch(p, value) {
			return true
		}
	}
	return false
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// wildcardMatch implements IAM's glob: `*` matches any run of characters, `?`
// matches exactly one.
//
// Iterative with backtracking rather than recursive, so a pathological pattern
// from a catalog file — attacker-controlled input in the threat model — cannot
// blow the stack. A catalog is not a hot path, but "the compiler crashed on a
// crafted catalog" is a finding either way.
func wildcardMatch(pattern, value string) bool {
	var pi, vi, star, mark int
	star = -1
	for vi < len(value) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi]):
			pi++
			vi++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = vi
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			vi = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// DeniedActions returns every action in the probe set that the statements deny
// for the given principal, for reporting in a test failure.
//
// A property test failure that says "the merge permits something an input denied"
// is unactionable without naming which call, and the shrunk counterexample rapid
// produces is a statement set, not a request.
func DeniedActions(statements []Statement, probes []Request) []string {
	var out []string
	for _, r := range probes {
		if Denies(statements, r) {
			out = append(out, r.Action+"@"+r.Region+" as "+r.Principal)
		}
	}
	sort.Strings(out)
	return out
}
