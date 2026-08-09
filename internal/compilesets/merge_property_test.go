// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// combine is Combine plus a fatal check on the error, for this file's
// generators only: drawMerged/drawRenderable never populate ConfigRules, so
// Combine here can never return a *ConflictReport — a non-nil error is a
// bug in this file's generators or in Combine itself, either of which
// TestUnionIsMonotone and its siblings should fail loudly on rather than
// silently ignore.
func combine(rt *rapid.T, a, b *Merged) *Merged {
	u, err := Combine(a, b)
	if err != nil {
		rt.Fatalf("Combine: %v (drawMerged/drawRenderable do not generate ConfigRules, so this "+
			"should be unreachable)", err)
	}
	return u
}

// Property tests for the SCP union (DESIGN §9).
//
//	idempotence   A ∪ A = A
//	commutativity A ∪ B = B ∪ A
//	associativity (A ∪ B) ∪ C = A ∪ (B ∪ C)
//	monotonicity  if either A or B forbids a behavior, A ∪ B forbids it
//
// Monotonicity is the one that matters, and ROADMAP names it in the operational
// form: can any merge WIDEN permissions. It is asserted here over the set of
// denied requests — see behavior.go for why over behavior rather than over bytes.
//
// The other three are what make Combine a meet on a semilattice, which is what
// lets `compile` and `vend` merge the same control sets in any order and get the
// same policy. They are asserted over denied behavior too, and separately over
// the canonical statement keys: two statement sets can deny the same behavior
// over any finite probe set by accident, and the key comparison catches a
// difference the probes miss.
//
// # What the generator is for
//
// The generated statements are drawn from a small vocabulary — a handful of
// actions, principals, regions, conditions — on purpose. The bug this suite
// hunts is not "an unusual action name breaks the merger"; it is "two statements
// that differ in one field get combined and a constraint is lost". That bug
// needs COLLISIONS: statements that agree on three fields and differ on the
// fourth, which is exactly what a small vocabulary produces and a wide one
// almost never does. A generator drawing random strings would produce statements
// that never merge, and a suite where tryMerge never fires would pass while
// testing nothing.

// The vocabulary. Small and overlapping, so that generated statements collide
// along one axis often.
var (
	probeActions = []string{
		"config:DeleteConfigurationRecorder",
		"config:StopConfigurationRecorder",
		"cloudtrail:StopLogging",
		"cloudtrail:DeleteTrail",
		"iam:CreateUser",
		"s3:PutBucketPolicy",
	}

	// probeActionSets are the action lists a statement may carry, sampled from as
	// a WHOLE rather than assembled per statement.
	//
	// This is the difference between a suite that tests the merger and one that
	// looks like it does. Drawing 1-3 actions independently out of six gives two
	// statements the same action list about one draw in twenty, and axis 1 — same
	// actions, different exemptions, the merge that would WIDEN if it concatenated
	// — only fires when they collide. The first run of
	// TestTheGeneratorActuallyProducesMerges reported zero axis-1 merges and zero
	// dedupes over 100 draws, meaning the intersection this package exists to get
	// right was never exercised by a property. Sampling whole sets from a short
	// list makes collisions the common case.
	probeActionSets = [][]string{
		{"config:DeleteConfigurationRecorder"},
		{"config:StopConfigurationRecorder"},
		{"config:DeleteConfigurationRecorder", "config:StopConfigurationRecorder"},
		{"cloudtrail:StopLogging", "cloudtrail:DeleteTrail"},
		{"iam:CreateUser"},
		{"s3:PutBucketPolicy"},
	}

	probePrincipals = []string{
		"arn:aws:iam::111111111111:role/break-glass",
		"arn:aws:iam::111111111111:role/central-it",
		"arn:aws:iam::111111111111:role/researcher",
		artifact.AutomationRolePlaceholder,
	}

	// probeExemptSets are the exemption principal lists, sampled whole for the
	// same reason as the action sets: axis 2 requires two statements to agree on
	// their exemptions exactly, including agreeing on having none.
	probeExemptSets = [][]string{
		nil,
		{"arn:aws:iam::111111111111:role/break-glass"},
		{"arn:aws:iam::111111111111:role/central-it"},
		{"arn:aws:iam::111111111111:role/break-glass", "arn:aws:iam::111111111111:role/central-it"},
		{artifact.AutomationRolePlaceholder},
	}

	// probeResources are the resource lists a statement may carry.
	//
	// # Every entry used to be a single-element list, and that starved the suite
	//
	// AUDIT-2 H5 was a non-injective key encoding: the guard's fields and each
	// field's members were joined on control bytes, so one member carrying a
	// separator keyed the same as two members, and an empty member keyed the same as
	// no member at all. Two distinct guards then merged, and the merged statement
	// carried the union of their actions under whichever guard seeded the group — a
	// widening, and TestUnionIsMonotone is precisely the property that should have
	// caught it.
	//
	// It did not, and not because the assertion was wrong. A collision needs TWO
	// members on some axis, and this list had no two-member entry, so the generator
	// could not draw the shape. The property reported green over every run while
	// being structurally incapable of reaching the defect class. That is the
	// dangerous kind of green: nothing about the passing run said its inputs
	// excluded the bug.
	//
	// So the vocabulary carries the shapes now, and the property is the pin. Three
	// entries were added, each for a distinct reason:
	//
	//   - Two real members, which is what makes a collision expressible at all.
	//   - One member joining those two with the old list separator. Against the
	//     pre-fix encoding this and the entry above key identically, and
	//     TestUnionIsMonotone fails with "B denied 12 requests that A ∪ B permits".
	//   - The empty-string member, which needed no control byte: it joined to "",
	//     which is what an absent list joined to. This was the one that neutralized a
	//     root-user Deny in the probe — the merged Resource became [""], which
	//     matches nothing, so the Deny was in the document and inert.
	//   - nil, the ABSENT list, which is the other half of that pair. {""} on its own
	//     collides with nothing: it needs the shape it is indistinguishable FROM to be
	//     drawable too. Verified rather than assumed — against the pre-fix encoding in
	//     a throwaway worktree, the two-member and separator entries fail
	//     TestUnionIsMonotone in 71 draws, {""} alone passes, and {""} with nil fails
	//     in 26 with "B denied 48 requests that A ∪ B permits".
	//
	// nil also used to panic narrowedAnExemption on in.Resource[0] (merge_test.go),
	// which is why it looked like it had to be left out. That helper is fixed instead:
	// a statement with no resource is not an invalid statement, it is the ordinary
	// shape, and the renderer supplies "*" for it.
	probeResources = [][]string{
		{"*"},
		{"arn:aws:s3:::institution-*"},
		{"arn:aws:s3:::institution-data", "arn:aws:s3:::other-data"},
		{"arn:aws:s3:::institution-data\x01arn:aws:s3:::other-data"},
		{""},
		nil,
	}
	probeRegions    = []string{"us-east-1", "us-west-2", "eu-west-1"}
	probeConditions = []artifact.Condition{
		nil,
		{"StringNotEquals": {"aws:RequestedRegion": {"us-east-1"}}},
		{"Bool": {"aws:SecureTransport": {"false"}}},
	}
)

// probeRequests is the finite set of behaviors the properties are checked over:
// every action crossed with every principal and region, plus the resources that
// appear in the vocabulary.
//
// Enumerated once rather than generated, so that a failure names the same request
// on every run and the shrunk counterexample is the statement set — which is the
// thing a developer has to reason about.
var probeRequests = func() []Request {
	var out []Request
	resources := []string{"*", "arn:aws:s3:::institution-data", "arn:aws:s3:::other-data"}
	for _, a := range probeActions {
		for _, p := range probePrincipals {
			for _, r := range probeRegions {
				for _, res := range resources {
					out = append(out, Request{
						Principal: p,
						Action:    a,
						Resource:  res,
						Region:    r,
						// Both values of the one boolean key in the vocabulary
						// appear, because a condition the probe never satisfies
						// makes every statement carrying it dead weight in the
						// property.
						Conditions: map[string]string{"aws:SecureTransport": "false"},
					})
					out = append(out, Request{
						Principal:  p,
						Action:     a,
						Resource:   res,
						Region:     r,
						Conditions: map[string]string{"aws:SecureTransport": "true"},
					})
				}
			}
		}
	}
	return out
}()

// drawRestatement generates a statement that, with some probability, restates one
// already drawn — same meaning, different Sid and different exemption wording.
//
// This models the thing that actually produces duplicate statements in
// production, and it is the reason DESIGN §9 says "dedupe identical statements"
// at all: two frameworks stating one requirement. CMMC and 800-171 both prohibit
// disabling the audit log, each names it differently, and the merged policy must
// spend one slot on it rather than two.
//
// It exists because the vocabulary alone would not produce enough of them. The
// semantic key space here is around 180 wide, so two independent draws collide
// about once in 180 — TestTheGeneratorActuallyProducesMerges measured 10 in 2400
// and rightly failed its floor. Widening the collision rate by shrinking the
// vocabulary would have cost coverage on every other axis; restating is both more
// realistic and more targeted.
//
// The restatement redraws the Sid and the reasons, never the meaning: those are
// exactly the fields statementKey and exemptKey ignore, so a dedupe that depends
// on them agreeing is a dedupe that would not fire on two real frameworks.
// The restatement rate is one in four rather than one in two, because a
// restatement displaces a fresh draw and the fresh draws are what produce the
// exemption intersections. At even odds the generator's own honesty check
// measured 1224 dedupes against 25 intersections — a suite heavily exercising the
// cheapest path and barely reaching the one that can widen a policy.
const restateInN = 4

func drawRestatement(t *rapid.T, label string, prior []artifact.SCPStatement) artifact.SCPStatement {
	if len(prior) == 0 || rapid.IntRange(0, restateInN-1).Draw(t, label+".restates") != 0 {
		return drawStatement(t, label)
	}
	base := prior[rapid.IntRange(0, len(prior)-1).Draw(t, label+".restatesWhich")]

	out := cloneStatement(base)
	out.Sid = rapid.SampledFrom([]string{"DenyA", "DenyB", "ProtectBaseline"}).Draw(t, label+".sid")
	if len(out.ExemptPrincipals) > 0 {
		reworded := make(artifact.ExemptPrincipals, 0, len(out.ExemptPrincipals))
		for i, e := range out.ExemptPrincipals {
			reworded = append(reworded, artifact.ExemptPrincipal{
				Principal: e.Principal,
				Reason: rapid.SampledFrom([]string{"break-glass", "audited exception", "central IT operations"}).
					Draw(t, fmt.Sprintf("%s.reason%d", label, i)),
			})
		}
		out.ExemptPrincipals = reworded.Canonical()
	}
	return out
}

// drawStatement generates one SCP statement fragment.
func drawStatement(t *rapid.T, label string) artifact.SCPStatement {
	actions := rapid.SampledFrom(probeActionSets).Draw(t, label+".action")

	var exempt artifact.ExemptPrincipals
	for _, p := range rapid.SampledFrom(probeExemptSets).Draw(t, label+".exempt") {
		exempt = append(exempt, artifact.ExemptPrincipal{
			Principal: p,
			// The reason varies, because intersectExempt matches on the principal
			// alone and joins the reasons: a generator that always produced the
			// same text would never exercise joinReasons, and joinReasons is where
			// commutativity and associativity could break on a string concatenation
			// — as they did, on the first run of this suite.
			Reason: rapid.SampledFrom([]string{"break-glass", "audited exception", "central IT operations"}).
				Draw(t, label+".reason"),
		})
	}

	st := artifact.SCPStatement{
		// The Sid varies independently of the statement's meaning, because
		// statementKey deliberately excludes it. If a Sid ever leaked into the
		// merge decision, these properties would start failing — which is the
		// point of drawing it rather than fixing it.
		Sid:              rapid.SampledFrom([]string{"DenyA", "DenyB", "ProtectBaseline"}).Draw(t, label+".sid"),
		Effect:           "Deny",
		Action:           actions,
		Resource:         rapid.SampledFrom(probeResources).Draw(t, label+".resource"),
		Condition:        rapid.SampledFrom(probeConditions).Draw(t, label+".condition"),
		ExemptPrincipals: exempt,
	}
	// Canonicalize the way a loaded artifact would be, so the properties are
	// stated over the same shape the vend path sees.
	stmt := cloneStatement(st)
	return stmt
}

// drawMerged generates a Merged directly, rather than an artifact.
//
// Directly, because Combine is the operation under test and going through
// FromArtifact would make every property also a property of artifact decoding —
// so a failure would not say which. The allowlists are drawn here too, since they
// are half of what Combine intersects.
func drawMerged(t *rapid.T, label string) *Merged {
	n := rapid.IntRange(0, 4).Draw(t, label+".n")
	m := &Merged{}
	var drawn []artifact.SCPStatement
	for i := 0; i < n; i++ {
		// Later statements may restate an earlier one, the way two frameworks in
		// one compile restate a shared requirement.
		st := drawRestatement(t, fmt.Sprintf("%s.st%d", label, i), drawn)
		drawn = append(drawn, st)
		m.Statements = append(m.Statements, Statement{
			SCPStatement: st,
			Origins:      []string{fmt.Sprintf("%s:control-%d", label, i)},
		})
	}
	m.Statements = mergeStatements(m.Statements)
	sortStatements(m.Statements)

	if rapid.Bool().Draw(t, label+".hasRegions") {
		m.RegionAllowlist = newAllowSet(
			rapid.SliceOfNDistinct(rapid.SampledFrom(probeRegions), 1, 3,
				func(s string) string { return s }).Draw(t, label+".regions"),
			label+":regions")
	}
	if rapid.Bool().Draw(t, label+".hasServices") {
		m.ServiceAllowlist = newAllowSet(
			rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"s3", "ec2", "lambda", "batch"}), 1, 3,
				func(s string) string { return s }).Draw(t, label+".services"),
			label+":services")
	}
	return m
}

// deniedSet returns the probe requests the statement set denies, as a comparable
// string set.
func deniedSet(sts []Statement) map[string]bool {
	out := map[string]bool{}
	for _, r := range probeRequests {
		if Denies(sts, r) {
			out[requestKey(r)] = true
		}
	}
	return out
}

func requestKey(r Request) string {
	return strings.Join([]string{
		r.Principal, r.Action, r.Resource, r.Region, r.Conditions["aws:SecureTransport"],
	}, "|")
}

// mergedKey is the canonical identity of a Merged: every statement key plus both
// allowlists, with nil distinguished from empty.
//
// Used by idempotence, commutativity, and associativity in addition to the denied
// sets, because the probe set is finite: two genuinely different statement lists
// could deny the same probes and differ on a request nobody enumerated. Equality
// here is the stronger claim, and it is the one that makes a golden file stable.
func mergedKey(m *Merged) string {
	var sb strings.Builder
	for _, st := range m.Statements {
		sb.WriteString(statementKey(st))
		sb.WriteString("\x05")
		// Exemption reasons are outside statementKey (it keys on the principal)
		// but they are rendered into the policy for a human to read, so a merge
		// that produced a different reason text in a different order is a
		// commutativity failure worth catching.
		for _, e := range st.ExemptPrincipals {
			sb.WriteString(e.Principal)
			sb.WriteString("=")
			sb.WriteString(e.Reason)
			sb.WriteString(";")
		}
		sb.WriteString("\x06")
	}
	sb.WriteString("\x07")
	sb.WriteString(allowKey(m.RegionAllowlist))
	sb.WriteString("\x07")
	sb.WriteString(allowKey(m.ServiceAllowlist))
	return sb.String()
}

func allowKey(s *AllowSet) string {
	if s == nil {
		return "<nil>"
	}
	return "[" + strings.Join(sortedUnique(s.Members), ",") + "]"
}

// diffDenied returns the requests in want that are missing from got.
func diffDenied(want, got map[string]bool) []string {
	var missing []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	return sortedUnique(missing)
}

// TestUnionIsMonotone is the can-any-merge-widen property, and it is the reason
// this package has property tests at all.
//
// Every behavior either input denied, the union must deny. A counterexample is a
// merge that widened permissions — the exact defect DESIGN §9 forbids and the one
// a merger can commit while every input catalog stays correct.
func TestUnionIsMonotone(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		b := drawMerged(rt, "b")
		u := combine(rt, a, b)

		denied := deniedSet(u.Statements)
		for _, side := range []struct {
			name string
			m    *Merged
		}{{"A", a}, {"B", b}} {
			want := deniedSet(side.m.Statements)
			if missing := diffDenied(want, denied); len(missing) > 0 {
				rt.Fatalf("the union WIDENED permissions: %s denied %d request(s) that A ∪ B permits.\n"+
					"first missing: %s\n%s\nunion:\n%s",
					side.name, len(missing), missing[0], describe(side.name, side.m), describe("A ∪ B", u))
			}
		}
	})
}

// TestUnionIsMonotoneOnAllowlists is monotonicity for the intersected
// allowlists, stated separately because an allowlist is not a statement until
// Pack renders it — so the statement-level property above cannot see it.
//
// The claim: the union's allowlist permits no member that either input's
// allowlist forbade. For an intersection that means the result is a subset of
// each constrained side, and that a side which constrained nothing does not
// magically constrain.
func TestUnionIsMonotoneOnAllowlists(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		b := drawMerged(rt, "b")
		u := combine(rt, a, b)

		for _, axis := range []struct {
			name string
			pick func(*Merged) *AllowSet
		}{
			{"region", func(m *Merged) *AllowSet { return m.RegionAllowlist }},
			{"service", func(m *Merged) *AllowSet { return m.ServiceAllowlist }},
		} {
			got := pickMembers(axis.pick(u))
			for _, side := range []struct {
				name string
				m    *Merged
			}{{"A", a}, {"B", b}} {
				set := axis.pick(side.m)
				if set == nil {
					continue
				}
				permitted := map[string]bool{}
				for _, v := range set.Members {
					permitted[v] = true
				}
				for _, v := range got {
					if !permitted[v] {
						rt.Fatalf("the union WIDENED the %s allowlist: it permits %q, which %s forbids "+
							"(%s permits %v, union permits %v)",
							axis.name, v, side.name, side.name, set.Members, got)
					}
				}
			}
			// And an unconstrained union means neither side constrained: an
			// intersection cannot drop a constraint entirely.
			if axis.pick(u) == nil && (axis.pick(a) != nil || axis.pick(b) != nil) {
				rt.Fatalf("the union LOST the %s allowlist: one input constrained it and the union does not",
					axis.name)
			}
		}
	})
}

func pickMembers(s *AllowSet) []string {
	if s == nil {
		return nil
	}
	return s.Members
}

// TestUnionIsMonotoneOnTheGlobalServiceExemptionList is monotonicity for the
// exemption list, which is the one set in a Merged where "wider" and "longer" are
// the same thing.
//
// The list is rendered into NotAction, so every namespace on it is a HOLE in a
// Deny. A merge that unioned the lists would punch a hole neither input granted —
// the same defect as unioning exempt principals, one layer down and easier to miss
// because the entries look like a compatibility list rather than like permissions.
func TestUnionIsMonotoneOnTheGlobalServiceExemptionList(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawRenderable(rt, "a")
		b := drawRenderable(rt, "b")
		u := combine(rt, a, b)

		got := pickMembers(u.RegionDenyExemptServices)
		for _, side := range []struct {
			name string
			m    *Merged
		}{{"A", a}, {"B", b}} {
			spared := map[string]bool{}
			for _, v := range side.m.RegionDenyExemptServices.Members {
				spared[v] = true
			}
			for _, v := range got {
				if !spared[v] {
					rt.Fatalf("the union WIDENED the global-service exemption list: it spares %q from the "+
						"region and service Denies, which %s does not (%s spares %v, union spares %v). "+
						"Every entry on this list is a hole in a Deny, so a longer list is a wider policy",
						v, side.name, side.name, side.m.RegionDenyExemptServices.Members, got)
				}
			}
		}
		if u.RegionDenyExemptServices == nil {
			rt.Fatal("the union LOST the exemption list; both inputs carried one, and a Merged without one " +
				"cannot render either allowlist at all")
		}
	})
}

// TestUnionIsMonotoneOverRenderedPolicies is the can-any-merge-widen property with
// the REGION AND SERVICE SETS as subjects rather than only the statements.
//
// Why a separate property, when TestUnionIsMonotone already checks denied behavior:
// an allowlist is not a statement until Pack renders it, so the statement-level
// property cannot see it, and TestUnionIsMonotoneOnAllowlists sees it only as a set
// of member strings. Neither notices a renderer that intersected the members
// correctly and then emitted a policy permitting more than either input's would —
// a condition operator changed, a NotAction list assembled from the wrong side, an
// exemption list resolved per statement instead of once. The subject here is the
// document that actually gets attached to the OU.
//
// The refusal case is not a widening. If the union's allowlists or exemption lists
// intersect to nothing, Pack refuses and nothing is attached; a policy that does
// not exist permits nothing. So the property is checked only when the union packs,
// and TestTheRenderedMonotonicityPropertyIsNotMostlyRefusals keeps that from
// quietly becoming the usual case.
//
// # The subject is the parsed document, and it was not always
//
// AUDIT-2 finding H1. This property read Policy.Statements — the struct list Pack
// carries alongside each document for `verify`'s benefit — which is the packer's
// INPUT to rendering, not its output. Every widening this comment claims to catch
// happens strictly downstream of that field: renderStatement builds the JSON from
// the struct, so a renderer that emitted a wider NotAction, a looser condition
// operator, or an extra exemption ARN left Statements untouched and the property
// compared two unchanged copies of it. Both jam-checks confirmed it — appending
// "*" to the rendered NotAction, and appending a wildcard role ARN to the rendered
// ArnNotLike, each passed this property and were caught only by a golden file.
//
// So the document is parsed back with the same reader `verify` uses, and the model
// evaluates THAT. Which also closes the gap the other way: a golden file says
// "these bytes changed", and only a behavioral comparison says "and the change
// permits more".
func TestUnionIsMonotoneOverRenderedPolicies(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawRenderable(rt, "a")
		b := drawRenderable(rt, "b")
		u := combine(rt, a, b)

		union, err := Pack(u, packOpts())
		if err != nil {
			// A compile the packer refuses. Nothing is attached, so nothing widened.
			return
		}
		denied := deniedSet(reparsedStatements(rt, union))

		for _, side := range []struct {
			name string
			m    *Merged
		}{{"A", a}, {"B", b}} {
			p, perr := Pack(side.m, packOpts())
			if perr != nil {
				rt.Fatalf("%s does not pack on its own (%v); the generator is supposed to produce "+
					"renderable inputs, so this is a generator bug and it makes the property vacuous",
					side.name, perr)
			}
			want := deniedSet(reparsedStatements(rt, p))
			if missing := diffDenied(want, denied); len(missing) > 0 {
				rt.Fatalf("the union's PACKED POLICY widened permissions: %s's packed policy denied %d "+
					"request(s) the union's permits.\nfirst missing: %s\n%s\nunion:\n%s",
					side.name, len(missing), missing[0], describe(side.name, side.m), describe("A ∪ B", u))
			}
		}
	})
}

// TestTheRenderedPropertyReadsTheDocumentAndNotTheStatementField is the pin on
// H1's fix.
//
// The defect it prevents recurring is subtle in exactly the way that matters: the
// property still passed, still ran its full generator, still reported the right
// number of checks. Nothing about a green run said that its subject was one field
// upstream of the bytes. So this asserts the two lists are DIFFERENT objects
// derived by different code paths, by finding a case where they disagree — the
// automation-role placeholder, which Policy.Statements carries symbolically and
// the rendered document carries as a materialized ARN.
//
// If a future refactor makes reparsedStatements a synonym for packedStatements,
// this fails, and the failure names the reason rather than a diff.
func TestTheRenderedPropertyReadsTheDocumentAndNotTheStatementField(t *testing.T) {
	m := &Merged{Statements: []Statement{{
		SCPStatement: artifact.SCPStatement{
			Sid:              "probe",
			Effect:           "Deny",
			Action:           []string{"config:StopConfigurationRecorder"},
			ExemptPrincipals: artifact.ExemptPrincipals{{Principal: artifact.AutomationRolePlaceholder, Reason: "probe"}},
		},
	}}}
	p := mustPack(t, m, packOpts())

	fromField := packedStatements(p)
	if len(fromField) != 1 {
		t.Fatalf("expected one statement in the field, got %d", len(fromField))
	}
	if got := fromField[0].ExemptPrincipals; len(got) != 1 || got[0].Principal != artifact.AutomationRolePlaceholder {
		t.Fatalf("Policy.Statements no longer carries the symbolic placeholder (%v); this test's premise "+
			"is gone, so find another field on which the struct and the document disagree", got)
	}

	fromDoc := reparsedStatements(t, p)
	if len(fromDoc) != 1 {
		t.Fatalf("expected one statement parsed back from the document, got %d", len(fromDoc))
	}
	arns := fromDoc[0].Condition["ArnNotLike"]["aws:PrincipalArn"]
	if len(arns) != 1 || arns[0] != testAutomationRole {
		t.Fatalf("the reparsed statement does not carry the MATERIALIZED role ARN (%v, want [%s]); "+
			"reparsedStatements is reading something other than Policy.Document, so the rendered "+
			"monotonicity property is back to checking the packer's input", arns, testAutomationRole)
	}
	if strings.Contains(strings.Join(arns, ","), artifact.AutomationRolePlaceholder) {
		t.Error("the reparsed condition still holds the placeholder, so the two lists are the same data " +
			"and the rendered property is not reading the document")
	}
}

// reparsedStatements is Pack's output read back the way AWS would return it: the
// rendered document, parsed, mapped onto the statement type the behavioral model
// evaluates.
//
// Across ALL policies, not the first. The bin packer distributes statements over
// several documents, every document is attached to the same target, and a
// restriction that landed in the second one is as effective as one in the first.
// Reading only Policies[0] would report a widening every time a multi-document pack
// happened to split the allowlists off.
//
// Exemptions come back as a rendered ArnNotLike condition rather than as
// ExemptPrincipals, and that is left alone rather than reconstructed: the model
// evaluates the condition form correctly (behavior.go's ArnNotLike case), and
// reconstructing the struct field would be this helper re-deriving the very thing
// the property is checking. Condition is where an over-wide exemption shows up, so
// it has to arrive as a condition.
func reparsedStatements(t require, p *Packed) []Statement {
	var out []Statement
	for _, pol := range p.Policies {
		var parsed policyDocument
		if err := json.Unmarshal([]byte(pol.Document), &parsed); err != nil {
			t.Fatalf("policy %s is not readable JSON (%v); Pack asserts it parses before returning, so "+
				"this is a packer bug rather than a test problem:\n%s", pol.Name, err, pol.Document)
		}
		for _, st := range parsed.Statement {
			cond := artifact.Condition{}
			for op, keys := range st.Condition {
				cond[op] = map[string][]string{}
				for k, v := range keys {
					cond[op][k] = v.strings()
				}
			}
			if len(cond) == 0 {
				cond = nil
			}
			out = append(out, Statement{
				SCPStatement: artifact.SCPStatement{
					Sid:       st.Sid,
					Effect:    st.Effect,
					Action:    st.Action.strings(),
					Resource:  st.Resource.strings(),
					Condition: cond,
				},
				NotAction: st.NotAction.strings(),
			})
		}
	}
	return out
}

// require is the intersection of *testing.T and *rapid.T that reparsedStatements
// needs, so one helper serves the property and the pin above it.
type require interface {
	Fatalf(format string, args ...any)
}

// TestTheRenderedMonotonicityPropertyIsNotMostlyRefusals.
//
// The property above returns early when the union does not pack, which is correct
// and is also the shape of a property that tests nothing: if disjoint allowlist
// draws made most unions unpackable, it would report a pass having compared almost
// no policies. Same argument as TestTheGeneratorActuallyProducesMerges, and the
// same remedy — measure it.
func TestTheRenderedMonotonicityPropertyIsNotMostlyRefusals(t *testing.T) {
	const runs = 200
	var packed, refused int
	rapid.Check(t, func(rt *rapid.T) {
		if packed+refused >= runs {
			return
		}
		u := combine(rt, drawRenderable(rt, "a"), drawRenderable(rt, "b"))
		if _, err := Pack(u, packOpts()); err != nil {
			refused++
			return
		}
		packed++
	})
	t.Logf("%d unions packed, %d refused", packed, refused)
	if packed*4 < packed+refused {
		t.Errorf("only %d of %d generated unions packed; the rendered monotonicity property is mostly "+
			"returning early, so it is comparing policies far less often than its run count suggests. "+
			"Widen the drawn allowlists so intersections survive more often",
			packed, packed+refused)
	}
	if refused == 0 {
		t.Error("no generated union was refused, so the early return in the rendered monotonicity " +
			"property is dead code and the disjoint-allowlist case is unexercised by it")
	}
}

// packedStatements flattens a pack into the statement list the behavioral model
// evaluates.
//
// Across ALL policies, not the first: the bin packer distributes statements over
// several documents, every document is attached to the same target, and a
// restriction that landed in the second one is as effective as one in the first.
// Reading only Policies[0] would report a widening every time a multi-document pack
// happened to split the allowlists off.
func packedStatements(p *Packed) []Statement {
	var out []Statement
	for _, pol := range p.Policies {
		out = append(out, pol.Statements...)
	}
	return out
}

// drawRenderable is drawMerged plus the artifact-level exemption list Pack requires
// before it will render either allowlist, and with at least one allowlist present
// so the drawn value is actually a subject for the rendered properties.
//
// The exemption sets all contain the namespaces that would brick an account —
// deliberately, so their intersection is never empty and the refusals the rendered
// property returns early on are only ever the allowlist ones. The empty-intersection
// refusal has its own coverage (TestAnExemptionListThatIntersectsToNothingIsRefused
// and the pinned refusal text); mixing it in here would make the property's early
// return fire for two unrelated reasons.
func drawRenderable(t *rapid.T, label string) *Merged {
	m := drawMerged(t, label)
	if m.RegionAllowlist == nil && m.ServiceAllowlist == nil {
		m.RegionAllowlist = newAllowSet(
			rapid.SliceOfNDistinct(rapid.SampledFrom(probeRegions), 1, 3,
				func(s string) string { return s }).Draw(t, label+".forcedRegions"),
			label+":regions")
	}
	extra := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"kms", "route53", "support", "health"}), 0, 3,
		func(s string) string { return s }).Draw(t, label+".exemptExtra")
	m.RegionDenyExemptServices = newAllowSet(
		append([]string{"iam", "sts", "organizations"}, extra...), label+":exempt")
	return m
}

// TestUnionIsIdempotent: A ∪ A = A.
//
// Two claims in one, and both matter operationally. Denied behavior must be
// unchanged, or re-running a vend with the same control set twice would enforce
// something different the second time. And the canonical form must be unchanged,
// or the policy documents would differ and the ensure step would rewrite a policy
// it should have left alone.
func TestUnionIsIdempotent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		u := combine(rt, a, a)

		if got, want := mergedKey(u), mergedKey(a); got != want {
			rt.Fatalf("A ∪ A ≠ A.\n%s\n%s", describe("A", a), describe("A ∪ A", u))
		}
		if missing := diffDenied(deniedSet(a.Statements), deniedSet(u.Statements)); len(missing) > 0 {
			rt.Fatalf("A ∪ A permits %d request(s) A denies, e.g. %s", len(missing), missing[0])
		}
	})
}

// TestUnionIsCommutative: A ∪ B = B ∪ A.
//
// Order-independence is what lets `compile --set a --set b` and `--set b --set a`
// produce the same artifact, and it is what makes the packer's golden files a
// meaningful contract rather than a record of one argument order.
func TestUnionIsCommutative(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		b := drawMerged(rt, "b")

		ab, ba := combine(rt, a, b), combine(rt, b, a)
		if mergedKey(ab) != mergedKey(ba) {
			rt.Fatalf("A ∪ B ≠ B ∪ A.\n%s\n%s", describe("A ∪ B", ab), describe("B ∪ A", ba))
		}
	})
}

// TestUnionIsAssociative: (A ∪ B) ∪ C = A ∪ (B ∪ C).
//
// The property that makes Merge's fold well defined. Without it the result of
// merging three control sets would depend on the order the fold happened to
// bracket them in, which no operator could predict and no golden file could pin.
func TestUnionIsAssociative(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		b := drawMerged(rt, "b")
		c := drawMerged(rt, "c")

		left := combine(rt, combine(rt, a, b), c)
		right := combine(rt, a, combine(rt, b, c))
		if mergedKey(left) != mergedKey(right) {
			rt.Fatalf("(A ∪ B) ∪ C ≠ A ∪ (B ∪ C).\n%s\n%s",
				describe("(A ∪ B) ∪ C", left), describe("A ∪ (B ∪ C)", right))
		}
		if missing := diffDenied(deniedSet(left.Statements), deniedSet(right.Statements)); len(missing) > 0 {
			rt.Fatalf("the two groupings deny different behavior, e.g. %s", missing[0])
		}
	})
}

// TestCombineDoesNotMutateItsOperands.
//
// Combine narrows exemption lists, and a narrowing that wrote through a shared
// slice would make the SECOND merge of the same control set stricter than the
// first — which the idempotence property above would report as a semantic failure
// while the cause was aliasing. Worse, at vend time it would mean the artifact a
// caller still holds silently changed meaning.
func TestCombineDoesNotMutateItsOperands(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		b := drawMerged(rt, "b")
		beforeA, beforeB := mergedKey(a), mergedKey(b)

		_ = combine(rt, a, b)

		if mergedKey(a) != beforeA {
			rt.Fatalf("Combine mutated its left operand")
		}
		if mergedKey(b) != beforeB {
			rt.Fatalf("Combine mutated its right operand")
		}
	})
}

// TestEveryMergedStatementKeepsItsProvenance.
//
// Provenance is what makes a packed policy reviewable, and a merge is exactly
// where it can be dropped: the merged statement is built from one side, so
// forgetting to union the origins loses the other side's claim on it silently.
// Nothing about the policy's behavior would change, which is why only a test
// catches it.
func TestEveryMergedStatementKeepsItsProvenance(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		b := drawMerged(rt, "b")
		u := combine(rt, a, b)

		want := map[string]bool{}
		for _, side := range [][]Statement{a.Statements, b.Statements} {
			for _, st := range side {
				for _, o := range st.Origins {
					want[o] = true
				}
			}
		}
		got := map[string]bool{}
		for _, st := range u.Statements {
			if len(st.Origins) == 0 {
				rt.Fatalf("merged statement %q has no origins at all", st.Sid)
			}
			for _, o := range st.Origins {
				got[o] = true
			}
		}
		for o := range want {
			if !got[o] {
				rt.Fatalf("the union dropped provenance %q; a reviewer of the packed policy could not "+
					"tell which control set asked for the statement", o)
			}
		}
	})
}

// TestNoExemptionIsEffectiveThatBothSidesDidNotGrant is the widening case DESIGN
// §10 names, stated as a property.
//
// An exemption is the only thing in a catalog that widens a policy, so it is the
// only thing whose merge must be an intersection. The claim is about EFFECT, not
// about which statement carries which entry: if the union lets a principal
// perform an action, then every input must have let that principal perform it
// too. That is monotonicity restricted to the exemption axis, and it holds
// whatever the merger did with the lists.
//
// Stating it per-statement — "if the merged statement exempts P, both inputs'
// statements over that action must have exempted P" — is what a first draft of
// this test asserted, and it is WRONG, in the direction that matters. A statement
// set is a disjunction: one statement exempting a principal does not permit the
// call if another statement still denies it. An input carrying two statements over
// the same action, one exempting the break-glass role and one not, denies the
// break-glass role — so a union that preserves both statements verbatim, exempting
// nothing in effect, would fail the per-statement form while being exactly correct.
// The per-statement version tests a property of the representation. This tests the
// property of the policy.
func TestNoExemptionIsEffectiveThatBothSidesDidNotGrant(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawMerged(rt, "a")
		b := drawMerged(rt, "b")
		u := combine(rt, a, b)

		for _, r := range probeRequests {
			if Denies(u.Statements, r) {
				continue
			}
			// The union permits this call. Every side that denies it has had a
			// hole opened in it by the merge.
			for _, side := range []struct {
				name string
				m    *Merged
			}{{"A", a}, {"B", b}} {
				if Denies(side.m.Statements, r) {
					rt.Fatalf("the union grants %s an effective exemption for %s in %s that %s denies — "+
						"the merge opened a hole %s never agreed to.\n%s\n%s",
						r.Principal, r.Action, r.Region, side.name, side.name,
						describe(side.name, side.m), describe("A ∪ B", u))
				}
			}
		}
	})
}

// TestAnExemptionOnlyOneSideGrantedDoesNotSurviveAMerge is the same claim in the
// specific shape the merger can get wrong.
//
// The property test above would catch a concatenating intersectExempt only when
// the generator happened to draw two statements identical but for their exemption
// lists. This constructs exactly that pair, so the case is covered by a test whose
// failure names the defect rather than by a probabilistic draw.
func TestAnExemptionOnlyOneSideGrantedDoesNotSurviveAMerge(t *testing.T) {
	guard := func(exempt ...artifact.ExemptPrincipal) *Merged {
		return &Merged{Statements: []Statement{{
			SCPStatement: artifact.SCPStatement{
				Sid:              "ProtectRecorder",
				Effect:           "Deny",
				Action:           []string{"config:StopConfigurationRecorder"},
				Resource:         []string{"*"},
				ExemptPrincipals: artifact.ExemptPrincipals(exempt).Canonical(),
			},
			Origins: []string{"set:control"},
		}}}
	}
	const breakGlass = "arn:aws:iam::111111111111:role/break-glass"

	// A exempts the break-glass role; B does not.
	a := guard(artifact.ExemptPrincipal{Principal: breakGlass, Reason: "audited break-glass procedure"})
	b := guard()

	u := mustCombine(t, a, b)
	if len(u.Statements) != 1 {
		t.Fatalf("expected the two statements to merge into one, got %d:\n%s", len(u.Statements), describe("A ∪ B", u))
	}
	if got := u.Statements[0].ExemptPrincipals; len(got) != 0 {
		t.Fatalf("the merged statement exempts %v, but only one of the two control sets agreed to that hole; "+
			"exemption lists must INTERSECT, not concatenate (DESIGN §9, §10)", got)
	}

	req := Request{Principal: breakGlass, Action: "config:StopConfigurationRecorder", Resource: "*", Region: "us-east-1"}
	if !Denies(u.Statements, req) {
		t.Fatalf("the union permits the break-glass role to stop the configuration recorder, which control set B denies")
	}
}

// TestBothSidesExemptingOneRoleKeepsTheHoleAndBothReasons.
//
// The other half of the intersection, and the reason it matches on the principal
// rather than on the whole entry: two control sets that both agree to a hole,
// worded differently, agree about the hole. Dropping it would be over-strict — and
// an over-strict SCP breaks the research work automat exists to enable, which is a
// failure it cannot announce.
func TestBothSidesExemptingOneRoleKeepsTheHoleAndBothReasons(t *testing.T) {
	const breakGlass = "arn:aws:iam::111111111111:role/break-glass"
	guard := func(reason string) *Merged {
		return &Merged{Statements: []Statement{{
			SCPStatement: artifact.SCPStatement{
				Sid:      "ProtectRecorder",
				Effect:   "Deny",
				Action:   []string{"config:StopConfigurationRecorder"},
				Resource: []string{"*"},
				ExemptPrincipals: artifact.ExemptPrincipals{
					{Principal: breakGlass, Reason: reason},
				},
			},
			Origins: []string{"set:control"},
		}}}
	}

	u := mustCombine(t, guard("incident response"), guard("audited break-glass procedure"))
	if len(u.Statements) != 1 {
		t.Fatalf("expected one statement, got %d", len(u.Statements))
	}
	got := u.Statements[0].ExemptPrincipals
	if len(got) != 1 || got[0].Principal != breakGlass {
		t.Fatalf("both control sets exempted %s; the merge dropped the exemption: %v", breakGlass, got)
	}
	// Both justifications survive: a reviewer asking why the hole exists gets
	// both control sets' answers, not whichever one was merged first.
	for _, want := range []string{"incident response", "audited break-glass procedure"} {
		if !strings.Contains(got[0].Reason, want) {
			t.Errorf("the merged reason %q drops one control set's justification (%q)", got[0].Reason, want)
		}
	}
}

// describe renders a Merged for a failure message.
//
// A property test that reports only "not equal" costs an hour of bisecting;
// rapid's shrinking gets the counterexample small, and this makes it readable.
func describe(label string, m *Merged) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %d statement(s)", label, len(m.Statements))
	if m.RegionAllowlist != nil {
		fmt.Fprintf(&sb, ", regions=%v", m.RegionAllowlist.Members)
	}
	if m.ServiceAllowlist != nil {
		fmt.Fprintf(&sb, ", services=%v", m.ServiceAllowlist.Members)
	}
	sb.WriteString("\n")
	for _, st := range m.Statements {
		fmt.Fprintf(&sb, "    Deny %v on %v", st.Action, st.Resource)
		if len(st.NotAction) > 0 {
			fmt.Fprintf(&sb, " [NotAction %v]", st.NotAction)
		}
		if len(st.Condition) > 0 {
			fmt.Fprintf(&sb, " if %v", st.Condition)
		}
		for _, e := range st.ExemptPrincipals {
			fmt.Fprintf(&sb, "\n      except %s (%s)", e.Principal, e.Reason)
		}
		fmt.Fprintf(&sb, "\n      from %v\n", st.Origins)
	}
	return sb.String()
}
