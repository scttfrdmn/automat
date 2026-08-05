// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Merge combines the preventive halves of several artifacts into one statement
// set plus the intersected allowlists.
//
// The three operations, per DESIGN §9:
//
//   - Deny statements concatenate, then merge where a merge is exact.
//   - Region and service allowlists INTERSECT. "us-east-1,us-west-2" merged
//     with "us-east-1" is "us-east-1": permitting fewer regions is stricter.
//   - Exemption lists intersect, inside the statement merge.
//
// An empty result for an allowlist is meaningful and different from an absent
// one — see Merged.RegionAllowlist.
//
// Written as a fold over Combine rather than as one pass that accumulates
// everything, because a fold is what makes DESIGN §9's properties statable at
// all: associativity is a claim about grouping, and there is nothing to group
// without a binary operation. The n-ary form is the convenience; Combine is the
// operation.
func Merge(artifacts ...*artifact.Artifact) *Merged {
	acc := &Merged{}
	for _, a := range artifacts {
		acc = Combine(acc, FromArtifact(a))
	}
	return acc
}

// FromArtifact lifts one artifact's preventive half into a Merged.
//
// The within-artifact merge happens here too: one artifact can carry the same
// Deny under two control ids (a framework that states a requirement twice), and
// leaving those unmerged until Combine would make FromArtifact's output depend on
// whether anything was combined with it.
func FromArtifact(a *artifact.Artifact) *Merged {
	m := &Merged{}
	if a == nil {
		return m
	}
	for _, c := range a.Controls {
		if c.SCP == nil {
			continue
		}
		m.addSCP(c.SCP, a.Meta.ID, c.ID)
	}
	m.Statements = mergeStatements(m.Statements)
	sortStatements(m.Statements)
	return m
}

// Combine is the binary union of two merged control sets: the meet on permitted
// behavior that DESIGN §9 describes.
//
// It neither mutates nor aliases its inputs. Combine is called on the same
// operands repeatedly by the property tests — and, at vend time, on a Merged the
// caller may still hold — so an in-place narrowing of an exemption list would
// make the second call see a value the first produced. That is the shape of bug
// that makes a union look non-idempotent for reasons unrelated to its semantics.
//
// Statements are concatenated and renormalized rather than merged pairwise across
// the two sides. mergeStatements computes a normal form from the whole list at
// once (see its comment), so renormalizing the concatenation gives the same answer
// as normalizing either side alone would have — which is what makes Combine
// associative.
func Combine(a, b *Merged) *Merged {
	if a == nil && b == nil {
		return &Merged{}
	}
	if a == nil {
		a = &Merged{}
	}
	if b == nil {
		b = &Merged{}
	}

	sts := make([]Statement, 0, len(a.Statements)+len(b.Statements))
	for _, side := range [][]Statement{a.Statements, b.Statements} {
		for _, st := range side {
			sts = append(sts, copyStatement(st))
		}
	}

	out := &Merged{
		Statements:       mergeStatements(sts),
		RegionAllowlist:  intersectSets(a.RegionAllowlist, b.RegionAllowlist),
		ServiceAllowlist: intersectSets(a.ServiceAllowlist, b.ServiceAllowlist),
	}
	sortStatements(out.Statements)
	return out
}

// intersectSets intersects two accumulated allowlists.
//
// nil is the identity, not the empty set: a side that did not constrain regions
// must not be read as constraining them to nothing. That is the same nil-versus-
// empty distinction Merged.RegionAllowlist documents, and it is what makes
// Combine associative — with "nil means everything" the identity would depend on
// which side it appeared on.
func intersectSets(a, b *AllowSet) *AllowSet {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		return b.clone()
	case b == nil:
		return a.clone()
	}
	keep := make(map[string]bool, len(b.Members))
	for _, v := range b.Members {
		keep[v] = true
	}
	members := make([]string, 0, len(a.Members))
	for _, v := range a.Members {
		if keep[v] {
			members = append(members, v)
		}
	}
	return &AllowSet{
		Members: members,
		Sources: sortedUnique(append(append([]string(nil), a.Sources...), b.Sources...)),
	}
}

func (s *AllowSet) clone() *AllowSet {
	if s == nil {
		return nil
	}
	return &AllowSet{
		Members: append([]string(nil), s.Members...),
		Sources: append([]string(nil), s.Sources...),
	}
}

// copyStatement deep-copies the fields a merge can narrow, so Combine cannot
// reach back into an operand.
func copyStatement(st Statement) Statement {
	out := st
	out.SCPStatement = cloneStatement(st.SCPStatement)
	out.Origins = append([]string(nil), st.Origins...)
	out.NotAction = append([]string(nil), st.NotAction...)
	return out
}

// Merged is the merged preventive policy: statements plus the two intersected
// allowlists, with provenance for each statement.
type Merged struct {
	// Statements are the merged Deny fragments, in canonical order.
	Statements []Statement

	// RegionAllowlist is the intersection of every region allowlist that
	// appeared. nil means NO artifact constrained regions — unconstrained.
	//
	// The distinction between nil and empty is load-bearing and is why this is
	// not a plain []string with "empty means anything". An empty (non-nil)
	// intersection means two artifacts constrained regions and agreed on none,
	// which cannot be rendered as a policy: an SCP denying every region denies
	// everything, including the calls automat's own baseline needs. Pack reports
	// it as a conflict rather than emitting it.
	RegionAllowlist *AllowSet
	// ServiceAllowlist is the same for service namespaces.
	ServiceAllowlist *AllowSet
}

// AllowSet is an intersected allowlist that remembers who constrained it.
//
// Sources exist for the error message. When two artifacts intersect to nothing,
// the operator's question is immediately "which two?", and a conflict report
// that cannot answer it sends them to read every catalog by hand (CLAUDE.md
// rule 7).
type AllowSet struct {
	Members []string
	Sources []string
}

// Statement is a Deny fragment plus the artifacts and controls it came from.
//
// Provenance travels with the statement because the packer's output is what an
// auditor reads, and "which control set put this Deny here" is the first
// question asked of a merged policy. It is also what makes a conflict report
// name a file rather than a statement index.
type Statement struct {
	artifact.SCPStatement
	// Origins are "artifact-id:control-id" pairs, sorted and deduped.
	Origins []string

	// NotAction is the deny-everything-except form, and it exists on THIS type
	// rather than on artifact.SCPStatement on purpose.
	//
	// A Deny over NotAction denies everything it does not name, so two such
	// fragments concatenate into a deny-all — the opposite of the safe
	// concatenation DESIGN §9 rests on. artifact.SCPStatement therefore has no
	// such field and both its decoders reject one (AUDIT-0 finding H3), which
	// leaves the region and service allowlists with no way to be expressed: they
	// are genuinely "everything except", and they are intersected rather than
	// concatenated precisely because of it.
	//
	// So the packer owns the shape. Set in regionStatement and serviceStatement
	// and nowhere else, on statements that are appended AFTER mergeStatements has
	// run, so a NotAction statement never enters the normal form — where combining
	// two of them would produce the deny-all. TestNoAllowlistStatementIsEverMerged
	// holds that, and mergeStatements passes any such statement through untouched
	// as a second line of defense.
	NotAction []string
}

// isAllowlist reports whether the statement is one of the packer's own
// deny-everything-except renderings.
func (s Statement) isAllowlist() bool { return len(s.NotAction) > 0 }

func (m *Merged) addSCP(scp *artifact.SCP, artifactID, controlID string) {
	origin := artifactID + ":" + controlID
	for _, st := range scp.Statements {
		m.Statements = append(m.Statements, Statement{
			SCPStatement: cloneStatement(st),
			Origins:      []string{origin},
		})
	}
	if len(scp.RegionAllowlist) > 0 {
		m.RegionAllowlist = intersectSets(m.RegionAllowlist, newAllowSet(scp.RegionAllowlist, origin))
	}
	if len(scp.ServiceAllowlist) > 0 {
		m.ServiceAllowlist = intersectSets(m.ServiceAllowlist, newAllowSet(scp.ServiceAllowlist, origin))
	}
}

// newAllowSet seeds an allowlist from one control's constraint.
//
// The first constraint seeds the set and every later one narrows it, which is
// what makes nil mean "nobody constrained this" rather than "the intersection so
// far is everything" — an accumulator seeded with the universe would have to
// enumerate every AWS region, and would silently permit a region added to AWS
// after this build.
func newAllowSet(members []string, origin string) *AllowSet {
	return &AllowSet{Members: sortedUnique(members), Sources: []string{origin}}
}

// mergeStatements puts a statement list into normal form: one statement per
// distinct (guard, effective-exemption-set) pair.
//
// # Why a normal form and not a merge loop
//
// The first version of this merged pairwise to a fixed point — find two
// statements differing along exactly one axis, combine them, repeat. Every merge
// it made was exact, and it was still wrong, because greedy pairwise merging is
// not CONFLUENT: which pair merges first changes what remains mergeable. Given
// three control sets, (A ∪ B) ∪ C collapsed two statements that A ∪ (B ∪ C) left
// separate — same denied behavior, different documents. That is an associativity
// failure, and DESIGN §9 asks for associativity by name. It surfaced as a
// property-test counterexample on the first run rather than as a code review
// note, which is the argument for having written the property tests.
//
// The normal form is derived from what an SCP statement set MEANS. A statement
// set is a disjunction: the call (principal p, action a) is denied iff some
// statement names a and does not exempt p. So for each action pattern a, define
//
//	E(a) = the INTERSECTION of the exemption sets of every statement naming a
//
// and the set denies (p, a) exactly when a is named at all and p ∉ E(a). That is
// an equivalence, not an approximation: p ∉ E(a) means some statement naming a
// failed to exempt p, which is precisely the statement that denies. So a
// statement set is fully described by its E map, and rebuilding one statement per
// distinct E value reproduces the behavior exactly while merging as far as any
// merge could.
//
// Confluence then falls out. The E map is built by intersection, which is
// idempotent, commutative, and associative; and the E map of the normal form is
// the E map of the input, so normalizing an already-normalized set changes
// nothing and normalizing after a later union gives the same answer as
// normalizing once at the end. The properties in merge_property_test.go hold by
// construction rather than by argument.
//
// # What this subsumes
//
// Both merge axes the package doc describes are special cases. Same actions,
// different exemptions → one E value per action, intersected: the merge that
// would WIDEN if it concatenated. Same exemptions, different actions → several
// actions sharing one E value, grouped: each action keeps the guard it arrived
// with. And the case the old code deliberately refused — both axes differing at
// once — is now handled correctly rather than skipped, because the grouping is
// per action rather than per statement pair. There is no longer an over-strict
// direction to avoid: an action never inherits another action's exemptions.
func mergeStatements(in []Statement) []Statement {
	groups := map[string]*guardGroup{}
	var order []string
	// passthrough carries the statements that have no place in the normal form.
	var passthrough []Statement

	for _, st := range in {
		// An allowlist statement never enters the normal form. A Deny over
		// NotAction denies everything it does not name, so it is not describable
		// by an E map over named actions, and combining two of them yields a
		// deny-all. The packer appends these after this function runs (see
		// renderable), so this branch is the belt to that braces:
		// TestNoAllowlistStatementIsEverMerged holds it either way.
		//
		// A statement with no actions is passed through too, rather than
		// vanishing: it denies nothing, which is a catalog bug the packer reports
		// by name. Dropping it here would silence that error.
		if st.isAllowlist() || len(st.Action) == 0 {
			passthrough = append(passthrough, st)
			continue
		}

		k := guardKey(st)
		g, ok := groups[k]
		if !ok {
			g = &guardGroup{template: st, actions: map[string]*actionFacts{}}
			groups[k] = g
			order = append(order, k)
		}
		g.add(st)
	}

	out := make([]Statement, 0, len(in)+len(passthrough))
	out = append(out, passthrough...)
	for _, k := range order {
		out = append(out, groups[k].statements()...)
	}
	sortStatements(out)
	return out
}

// guardGroup accumulates every statement sharing one guard — effect, resource,
// and condition.
//
// The guard is what must match exactly for two prohibitions to be about the same
// thing. A different resource is a different scope and a different condition is a
// different guard; combining across either would apply the union of the actions
// under whichever guard survived, and keeping the weaker one widens.
type guardGroup struct {
	// template supplies the guard fields. Every statement in the group agrees on
	// them by construction, so the first arrival is as good as any.
	template Statement
	actions  map[string]*actionFacts
}

// actionFacts is everything the inputs said about one action pattern under one
// guard.
type actionFacts struct {
	// exempt maps an exempt principal to its joined justification. This is E(a):
	// it starts as the first statement's exemption list and is intersected with
	// every later one.
	exempt map[string]string
	// origins are the artifact:control pairs that asked for this action to be
	// denied.
	origins []string
}

func (g *guardGroup) add(st Statement) {
	for _, action := range st.Action {
		facts, seen := g.actions[action]
		if !seen {
			facts = &actionFacts{exempt: map[string]string{}}
			for _, e := range st.ExemptPrincipals {
				facts.exempt[e.Principal] = e.Reason
			}
			g.actions[action] = facts
		} else {
			// Intersect. An exemption is the only thing in a catalog that widens a
			// policy, so it survives only where every control set constraining the
			// action agrees to it — the defect DESIGN §10 names is concatenating
			// here instead.
			next := make(map[string]string, len(facts.exempt))
			for _, e := range st.ExemptPrincipals {
				if prior, ok := facts.exempt[e.Principal]; ok {
					next[e.Principal] = joinReasons(prior, e.Reason)
				}
			}
			facts.exempt = next
		}
		facts.origins = sortedUnique(append(facts.origins, st.Origins...))
	}
}

// statements rebuilds the group's normal form: actions sharing an identical
// exemption map become one statement.
//
// Grouped by the whole exemption map — principals AND joined reasons — not by the
// principals alone. Two actions exempting the same principal for differently
// worded reasons therefore do not merge, which costs a policy slot and buys
// confluence: if they merged, the surviving statement would carry a reason text
// that depended on which actions happened to be grouped with it, and a later
// union that split the group would produce different text. Reasons are what a
// reviewer reads to decide whether a hole in a preventive control is justified,
// so they are not free to drift. The trade is quota against determinism, and
// determinism is what makes the golden files and the ensure step meaningful.
func (g *guardGroup) statements() []Statement {
	type bucket struct {
		actions []string
		origins []string
		exempt  map[string]string
	}
	buckets := map[string]*bucket{}
	for action, facts := range g.actions {
		k := exemptMapKey(facts.exempt)
		b, ok := buckets[k]
		if !ok {
			b = &bucket{exempt: facts.exempt}
			buckets[k] = b
		}
		b.actions = append(b.actions, action)
		// Origins are unioned across the bucket's actions, so a merged statement
		// names every control set that contributed any of its actions. This is
		// deliberately an over-approximation at the statement level: split the
		// bucket by a later union and both halves still name both control sets.
		// Provenance is reporting, not semantics — it is excluded from
		// statementKey and from the rendered document, so the imprecision cannot
		// affect a policy. The alternative, keying the bucket on origins, would
		// fragment every statement by control id and merge nothing at all.
		b.origins = sortedUnique(append(b.origins, facts.origins...))
	}

	out := make([]Statement, 0, len(buckets))
	for _, b := range buckets {
		st := Statement{
			SCPStatement: artifact.SCPStatement{
				Effect:           g.template.Effect,
				Action:           sortedUnique(b.actions),
				Resource:         append([]string(nil), g.template.Resource...),
				Condition:        cloneCondition(g.template.Condition),
				ExemptPrincipals: exemptFromMap(b.exempt),
			},
			Origins: b.origins,
		}
		st.Sid = derivedSid(st)
		out = append(out, st)
	}
	// Sorted before returning, so the map iteration above cannot leak into the
	// output order.
	sortStatements(out)
	return out
}

// sidPrefix and sidHashLen shape a derived Sid. IAM allows only letters and
// digits, so there is no separator to be had.
const (
	sidPrefix  = "Automat"
	sidHashLen = 16
)

// derivedSid computes a merged statement's Sid from its own content.
//
// A merged statement cannot inherit one. The first version took the Sid of
// whichever statement seeded its guard group, and the golden files caught what that
// produces: a guard is effect, resource, and condition, so every unconditional Deny
// on "*" lands in ONE group no matter what it denies, and each of that group's
// exemption buckets came out carrying the same inherited Sid. Two failures at once,
// and the second is the worse one:
//
//   - IAM requires a Sid to be unique within a policy document, so CreatePolicy
//     rejects the whole thing with MalformedPolicyDocument. Mid-vend, with the
//     account already created — the parked state.
//   - The Sid was wrong even where it was unique. A statement denying
//     iam:CreateUser was labeled ProtectCloudTrail, because a CloudTrail statement
//     happened to seed the group. The Sid is the only human-readable handle in a
//     rendered policy: it is what an auditor reads to find the control, and what an
//     operator greps for when a Deny blocks something. A confidently wrong label is
//     worse than an opaque one, because it stops the reader looking.
//
// Hence content-derived: a hash of the canonical statement key, which is exactly the
// identity the merge already reasons about. Two statements share a Sid iff they are
// the same statement, so uniqueness within a document follows from statements being
// deduped, and the same input always produces the same Sid — which is what the
// golden files and the idempotent ensure step need. Nothing reads a Sid back, so it
// carries no semantics; the origins list is where "which control set asked for this"
// lives, and it survives a merge intact.
//
// Opaque is the deliberate trade. A derived name like "DenyConfigStopRecorder"
// would read better, but it would have to be derived from the action list, and an
// action list that merges differently under a later union would rename the
// statement — reintroducing the drift this fixes, in the field a reviewer trusts.
// Hashed over the statement key AND the exemption reason text. statementKey keys
// exemptions on the principal alone — deliberately, because two entries naming one
// principal are one hole — but the buckets above split on principals and reasons
// both, so two buckets can differ only in wording. Keying on the narrower thing
// would hand them the same Sid.
func derivedSid(st Statement) string {
	var sb strings.Builder
	sb.WriteString(statementKey(st))
	for _, e := range st.ExemptPrincipals {
		sb.WriteString("\x08")
		sb.WriteString(e.Principal)
		sb.WriteString("\x09")
		sb.WriteString(e.Reason)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return sidPrefix + hex.EncodeToString(sum[:])[:sidHashLen]
}

// exemptFromMap turns an accumulated exemption map back into a canonical list.
func exemptFromMap(m map[string]string) artifact.ExemptPrincipals {
	if len(m) == 0 {
		return nil
	}
	out := make(artifact.ExemptPrincipals, 0, len(m))
	for principal, reason := range m {
		out = append(out, artifact.ExemptPrincipal{Principal: principal, Reason: reason})
	}
	return out.Canonical()
}

// exemptMapKey is the canonical identity of an exemption map, principals and
// reasons both.
func exemptMapKey(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	principals := make([]string, 0, len(m))
	for p := range m {
		principals = append(principals, p)
	}
	sort.Strings(principals)
	var sb strings.Builder
	for _, p := range principals {
		sb.WriteString(p)
		sb.WriteString("\x03")
		sb.WriteString(m[p])
		sb.WriteString("\x04")
	}
	return sb.String()
}

// guardKey is the canonical identity of a statement's guard: what must match for
// two prohibitions to be about the same thing.
func guardKey(st Statement) string {
	return strings.Join([]string{
		st.Effect,
		strings.Join(sortedUnique(st.Resource), "\x01"),
		conditionKey(st.Condition),
	}, "\x00")
}

// joinReasons combines two justifications for the same exemption into one.
//
// Set union over the separator, not concatenation. Concatenation would be
// commutative if sorted — "a" and "b" give "a / b" either way — but it would not
// be ASSOCIATIVE, and three control sets exempting one principal is the ordinary
// case, not a corner. Joining "b" with "c" and then with "a" yields "a / b / c";
// joining "c" with "a" first yields "a / c", and prepending "b" compares "b"
// against the whole string "a / c" and yields "a / c / b". Two orderings, two
// policy documents, one of which a golden file pins and the other of which fails
// CI for a reason that has nothing to do with the controls.
//
// Splitting on the separator means a reason that legitimately contains " / " is
// reordered alphabetically. That is a cosmetic cost paid to make the operation a
// genuine set union, which is what associativity requires.
func joinReasons(a, b string) string {
	if a == b {
		return a
	}
	parts := append(strings.Split(a, reasonSeparator), strings.Split(b, reasonSeparator)...)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(sortedUnique(out), reasonSeparator)
}

const reasonSeparator = " / "

// ---------------------------------------------------------------------------
// Canonical keys. Two statements are "the same" iff their keys match, so every
// comparison in this file goes through one of these rather than through
// reflect.DeepEqual — which would call a nil slice and an empty one different
// and merge two identical statements into two policy slots.
// ---------------------------------------------------------------------------

func statementKey(st Statement) string {
	var sb strings.Builder
	sb.WriteString(st.Effect)
	sb.WriteString("\x00")
	sb.WriteString(strings.Join(sortedUnique(st.Action), "\x01"))
	sb.WriteString("\x00")
	// NotAction in the key, so the two allowlist statements never collapse into
	// one another: they are both "Deny, Resource *, no Action", and a key that
	// omitted the field would make dedupeIdentical drop the service restriction
	// on the grounds that it looks like the region one.
	sb.WriteString(strings.Join(sortedUnique(st.NotAction), "\x01"))
	sb.WriteString("\x00")
	sb.WriteString(strings.Join(sortedUnique(st.Resource), "\x01"))
	sb.WriteString("\x00")
	sb.WriteString(conditionKey(st.Condition))
	sb.WriteString("\x00")
	sb.WriteString(exemptKey(st.ExemptPrincipals))
	// Sid is deliberately NOT in the key. Two catalogs denying the same actions
	// under the same conditions have written the same statement, and a differing
	// Sid is a naming choice, not a semantic difference — keying on it would
	// spend a policy slot per framework on a Deny they share, which is exactly
	// the quota pressure the packer exists to relieve.
	return sb.String()
}

func conditionKey(c artifact.Condition) string {
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

func exemptKey(es artifact.ExemptPrincipals) string {
	if len(es) == 0 {
		return ""
	}
	// Principal only. Two entries naming the same principal for different
	// reasons are the same hole, and guardGroup.add's intersection treats them as
	// such; a key that included the reason would make this file disagree with
	// that.
	names := make([]string, 0, len(es))
	for _, e := range es {
		names = append(names, e.Principal)
	}
	return strings.Join(sortedUnique(names), "\x01")
}

func sameStrings(a, b []string) bool {
	as, bs := sortedUnique(a), sortedUnique(b)
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// sortStatements puts the statement list in canonical order.
//
// Sorted by what the statement MEANS, not by Sid: the packer assigns Sids on
// output, and ordering by an input Sid would make the packed policy depend on a
// naming choice in a catalog file.
func sortStatements(sts []Statement) {
	sort.SliceStable(sts, func(i, j int) bool {
		return statementKey(sts[i]) < statementKey(sts[j])
	})
}

func cloneStatement(st artifact.SCPStatement) artifact.SCPStatement {
	out := st
	out.Action = sortedUnique(st.Action)
	out.Resource = sortedUnique(st.Resource)
	out.ExemptPrincipals = st.ExemptPrincipals.Canonical()
	out.Condition = cloneCondition(st.Condition)
	return out
}

func cloneCondition(c artifact.Condition) artifact.Condition {
	if len(c) == 0 {
		return nil
	}
	out := make(artifact.Condition, len(c))
	for op, keys := range c {
		dup := make(map[string][]string, len(keys))
		for k, vals := range keys {
			dup[k] = sortedUnique(vals)
		}
		out[op] = dup
	}
	return out
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
