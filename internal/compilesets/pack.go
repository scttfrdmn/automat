// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// AWS quotas the packer must fit inside (DESIGN §16).
const (
	// MaxPolicySize is the maximum SCP document size in characters.
	MaxPolicySize = 5120
	// MaxPoliciesPerTarget is the number of SCPs attachable to one target.
	MaxPoliciesPerTarget = 5

	// ReservedPolicySlots are the slots the packer must NOT consume: one for
	// central IT's institutional SCP above the delegated OU, and one for
	// FullAWSAccess, which AWS attaches to every target and whose removal denies
	// everything.
	//
	// Reserving them is the difference between a packer that fits and a packer
	// that fits in a test org. A university's delegated OU already has an
	// institutional policy on it, and a vend that consumed the last slot would
	// fail at attach time, after the account exists — the parked state, for a
	// reason the operator cannot fix without deleting somebody else's control.
	ReservedPolicySlots = 2

	// AvailablePolicySlots is what the packer may actually use.
	AvailablePolicySlots = MaxPoliciesPerTarget - ReservedPolicySlots

	// sizeHeadroom is held back from MaxPolicySize.
	//
	// The rendered document is not the last word on size: the automation role
	// ARN substituted for artifact.AutomationRolePlaceholder is longer than the
	// placeholder, and AWS's own size accounting has never been documented
	// precisely enough to bet a vend on. A packer that fills to exactly 5120
	// fails at attach time with an account already created.
	sizeHeadroom = 256
)

// UsablePolicySize is the document budget the packer packs against.
const UsablePolicySize = MaxPolicySize - sizeHeadroom

// Policy is one rendered SCP document ready to attach.
type Policy struct {
	// Name is the policy name automat ensures, e.g. "automat-cmmc-l1-1".
	Name string
	// Document is the rendered JSON policy.
	Document string
	// Statements are the merged statements this document carries, in the order
	// they were rendered. Kept so `verify` can report which control a finding
	// belongs to without re-parsing the document.
	Statements []Statement
}

// Packed is the packer's output.
type Packed struct {
	Policies []Policy
	// Warnings are non-fatal observations the operator should see — chiefly how
	// much of the quota was consumed. Printed rather than logged: an operator
	// three vends away from the policy limit needs to know before the vend that
	// hits it.
	Warnings []string
}

// PackError reports that the merged control set cannot be expressed within AWS's
// quotas, that the merge produced something unrenderable, or that a narrowing left
// nothing to render.
//
// An error value with remediation text, per CLAUDE.md rule 7: the operator's next
// action is to narrow the control set or split the OU, and the message says which
// and why.
type PackError struct {
	// Reason is what could not be done.
	Reason string
	// Remediation is what the operator should do about it.
	Remediation string
	// Sources names the artifacts involved, when known.
	Sources []string
	// Stage names the step that refused, and appears in the first clause of the
	// message. Empty means the packer, which is the ordinary case.
	//
	// It exists because Narrow refuses BEFORE anything is rendered, and a refusal
	// opening with "cannot pack" sends the operator to look at policy size and slot
	// quotas — the two things a narrowing failure has nothing to do with. The first
	// six words of an error are what a hurried operator reads, so they have to name
	// the right step.
	Stage string
}

func (e *PackError) Error() string {
	var sb strings.Builder
	if e.Stage != "" {
		sb.WriteString(e.Stage)
	} else {
		sb.WriteString("cannot pack the merged control set into service control policies")
	}
	sb.WriteString(": ")
	sb.WriteString(e.Reason)
	if len(e.Sources) > 0 {
		sb.WriteString(" (from ")
		sb.WriteString(strings.Join(sourcesShown(e.Sources), ", "))
		sb.WriteString(")")
	}
	sb.WriteString(". ")
	sb.WriteString(e.Remediation)
	return sb.String()
}

// maxSourcesShown caps the origin list in an error MESSAGE. The Sources field
// itself is never truncated — a caller rendering a conflict report wants all of
// them.
//
// The cap exists because the slot-overflow error's origin list is every control in
// every compiled set, which for a real union is hundreds of entries: an error whose
// remediation text scrolls off the top of the terminal has the same effect as no
// remediation text, which is the failure CLAUDE.md rule 7 exists to prevent. Eight
// is enough to see which control sets are involved, which is the question the list
// answers.
const maxSourcesShown = 8

func sourcesShown(sources []string) []string {
	if len(sources) <= maxSourcesShown {
		return sources
	}
	out := append([]string(nil), sources[:maxSourcesShown]...)
	return append(out, fmt.Sprintf("and %d more", len(sources)-maxSourcesShown))
}

// PackOptions parameterizes a pack.
type PackOptions struct {
	// NamePrefix prefixes every generated policy name. Required.
	NamePrefix string
	// AutomationRoleARN replaces artifact.AutomationRolePlaceholder in exemption
	// lists. Required if any statement carries the placeholder: the packer
	// refuses to render a symbolic principal into a policy, because IAM would
	// treat the unresolved string as a literal ARN that matches nothing, and the
	// exemption would silently not exist.
	AutomationRoleARN string
}

// Pack renders merged statements into as few SCP documents as will hold them.
//
// The algorithm is first-fit-decreasing over the statements in canonical order:
// render each statement, sort by rendered size descending, and place each into
// the first policy with room. First-fit-decreasing rather than optimal packing
// because the optimum is NP-hard, the input is tens of statements, and FFD is
// within 11/9 of optimal — which against a 3-slot budget means it finds a
// 3-policy packing whenever one plausibly exists.
//
// Sorting by size descending is what makes it deterministic: ties break on the
// canonical statement key, so the same input always produces the same bytes.
func Pack(m *Merged, opts PackOptions) (*Packed, error) {
	if opts.NamePrefix == "" {
		return nil, &PackError{
			Reason:      "no policy name prefix was given",
			Remediation: "this is a programming error in automat, not something a catalog can cause; report it",
		}
	}

	statements, err := m.renderable(opts)
	if err != nil {
		return nil, err
	}
	if len(statements) == 0 {
		// No preventive controls at all is legal — a control set may be entirely
		// detective. Returning an empty pack rather than an error means the vend
		// path does not need a special case, and `verify` reports the empty
		// enforcement-class count honestly.
		return &Packed{}, nil
	}

	rendered := make([]renderedStatement, 0, len(statements))
	for _, st := range statements {
		parts, err := renderFitting(st, opts)
		if err != nil {
			return nil, err
		}
		rendered = append(rendered, parts...)
	}

	// Decreasing by size, ties by canonical key.
	sort.SliceStable(rendered, func(i, j int) bool {
		if rendered[i].size != rendered[j].size {
			return rendered[i].size > rendered[j].size
		}
		return statementKey(rendered[i].Statement) < statementKey(rendered[j].Statement)
	})

	bins := firstFitDecreasing(rendered)
	if len(bins) > AvailablePolicySlots {
		return nil, &PackError{
			Reason: fmt.Sprintf("the merged statements need %d policies of %d characters, but only %d of "+
				"the %d policies attachable to a target are available to automat "+
				"(%d are reserved for the institutional policy and FullAWSAccess)",
				len(bins), UsablePolicySize, AvailablePolicySlots, MaxPoliciesPerTarget, ReservedPolicySlots),
			Remediation: "compile fewer control sets into one artifact, or attach the overflow at a parent OU " +
				"so its statements are inherited rather than attached here; SCP quotas are per target, and " +
				"inheritance does not consume a target's slots",
			Sources: allOrigins(statements),
		}
	}

	out := &Packed{Policies: make([]Policy, 0, len(bins))}
	for i, bin := range bins {
		name := fmt.Sprintf("%s-%d", opts.NamePrefix, i+1)
		doc, sts, err := assemble(bin)
		if err != nil {
			return nil, err
		}
		if len(doc) > MaxPolicySize {
			// Belt and braces: the bin packing accounts for this, so reaching
			// here means the accounting and the renderer disagree. Failing loudly
			// beats attaching a policy AWS will reject after the account exists.
			return nil, &PackError{
				Reason: fmt.Sprintf("policy %s assembled to %d characters, over the %d-character limit, "+
					"even though its statements were packed against a %d-character budget",
					name, len(doc), MaxPolicySize, UsablePolicySize),
				Remediation: "this is a bug in the packer's size accounting, not a catalog problem; report it",
			}
		}
		out.Policies = append(out.Policies, Policy{Name: name, Document: doc, Statements: sts})
	}

	out.Warnings = quotaWarnings(out.Policies)
	return out, nil
}

type renderedStatement struct {
	Statement
	body string
	size int
}

// renderFitting renders a statement, splitting its action list if the rendered
// form does not fit in one policy.
//
// # Why this exists
//
// The merge builds statements the packer then has to fit, and it groups actions by
// their exemption set — so an artifact whose controls share one exemption produces
// ONE statement carrying every action they name. That is the correct normal form and
// it is also unbounded: measuring the shipped baseline-protection set showed that
// merging enough protection controls with a common exemption yields a single
// statement of 5036 characters, which no policy can hold.
//
// Before this, that produced an error whose remediation said "split the control's
// action list across several statements in the catalog". Unactionable, and wrong
// about where the problem is: the catalog HAD split them, across seven controls;
// the merge joined them. An error telling an operator to undo something they did
// not do is worse than a crash, because they will try.
//
// # Why splitting cannot widen
//
// A Deny statement's action list is a disjunction — the statement denies action a
// iff a is in the list — so two statements over halves of the list deny exactly the
// union, which is the original set. Every other field is copied unchanged, so the
// guard and the exemptions are identical in each part. This is the exact inverse of
// what mergeStatements does when it groups actions sharing an exemption set, and it
// is safe for the same reason that grouping is: E(guard, action) is unchanged for
// every action.
//
// The split parts get their own derived Sids, since IAM requires uniqueness within
// a document and the parts can land in the same one.
func renderFitting(st Statement, opts PackOptions) ([]renderedStatement, error) {
	body, err := renderStatement(st, opts)
	if err != nil {
		return nil, err
	}
	if len(body)+policyEnvelopeSize <= UsablePolicySize {
		return []renderedStatement{{Statement: st, body: body, size: len(body)}}, nil
	}

	// An allowlist statement is not splittable. Its NotAction list is a
	// CONJUNCTION — it denies everything not named — so two statements over halves
	// of the list deny everything not in the first half OR not in the second,
	// which is everything. Splitting it would be the deny-all the whole NotAction
	// discipline exists to prevent (see Statement.NotAction), so this refuses
	// rather than trying.
	if st.isAllowlist() {
		return nil, &PackError{
			Reason: fmt.Sprintf("the %s allowlist renders to %d characters, which cannot fit in a "+
				"%d-character policy", allowlistKind(st), len(body)+policyEnvelopeSize, UsablePolicySize),
			Remediation: "shorten the allowlist: fewer permitted services, or fewer permitted regions. It " +
				"cannot be split across two policies — an allowlist denies everything it does not name, so " +
				"two halves would deny everything between them",
			Sources: st.Origins,
		}
	}
	if len(st.Action) < 2 {
		return nil, &PackError{
			Reason: fmt.Sprintf("statement %q renders to %d characters on a single action (%s), which cannot "+
				"fit in a %d-character policy", st.Sid, len(body)+policyEnvelopeSize,
				strings.Join(st.Action, ", "), UsablePolicySize),
			Remediation: "narrow the statement's condition, resource list, or exemption list in the catalog it " +
				"comes from; a statement denying one action cannot be split any further",
			Sources: st.Origins,
		}
	}

	// Halve and recurse. Halving rather than filling greedily to the budget: the
	// rendered size is not linear in the action count (the JSON escaping and the
	// separators are not), so a greedy fill would need its own size model, and a
	// second size model is a second thing to be wrong. Recursion depth is
	// log2(actions), so a 4096-action statement recurses twelve deep.
	mid := len(st.Action) / 2
	var out []renderedStatement
	for _, half := range [][]string{st.Action[:mid], st.Action[mid:]} {
		part := copyStatement(st)
		part.Action = append([]string(nil), half...)
		part.Sid = derivedSid(part)
		parts, err := renderFitting(part, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, parts...)
	}
	return out, nil
}

// allowlistKind names which allowlist a NotAction statement is, for the error
// above. The Sid is the packer's own and says so, but an operator reading "shorten
// the allowlist" needs to know which one.
func allowlistKind(st Statement) string {
	if _, ok := st.Condition["StringNotEquals"]["aws:RequestedRegion"]; ok {
		return "region"
	}
	return "service"
}

// policyEnvelopeSize is the fixed cost of the document around the statements:
// {"Version":"2012-10-17","Statement":[]} plus a comma per extra statement.
const policyEnvelopeSize = len(`{"Version":"2012-10-17","Statement":[]}`)

// firstFitDecreasing places each statement into the first bin with room.
func firstFitDecreasing(sts []renderedStatement) [][]renderedStatement {
	var bins [][]renderedStatement
	sizes := []int{}
	for _, st := range sts {
		placed := false
		for i := range bins {
			// +1 for the comma joining this statement to the previous.
			if sizes[i]+st.size+1 <= UsablePolicySize {
				bins[i] = append(bins[i], st)
				sizes[i] += st.size + 1
				placed = true
				break
			}
		}
		if !placed {
			bins = append(bins, []renderedStatement{st})
			sizes = append(sizes, policyEnvelopeSize+st.size)
		}
	}
	return bins
}

// assemble renders one bin into a policy document.
//
// Statements are re-sorted into canonical order within the bin, so the document
// does not read in size order — a human reviewing a packed policy should see
// related Denies together, and the bin's contents are already fixed by the time
// order affects nothing but readability.
func assemble(bin []renderedStatement) (string, []Statement, error) {
	sorted := append([]renderedStatement(nil), bin...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return statementKey(sorted[i].Statement) < statementKey(sorted[j].Statement)
	})

	var sb strings.Builder
	sb.WriteString(`{"Version":"2012-10-17","Statement":[`)
	sts := make([]Statement, 0, len(sorted))
	seenSid := make(map[string]bool, len(sorted))
	for i, st := range sorted {
		// IAM requires a Sid to be unique within a policy document and rejects the
		// whole policy with MalformedPolicyDocument otherwise — at CreatePolicy,
		// mid-vend, with the account already created. Checked here rather than
		// trusted from the merge because this is the last point before the API call
		// and because it is cheap: derivedSid makes collisions impossible by
		// construction, and an assertion that a construction holds is how the
		// construction stays true. The merge grew this bug once already (see
		// derivedSid) and it reached a golden file before anything caught it.
		if seenSid[st.Sid] {
			return "", nil, &PackError{
				Reason: fmt.Sprintf("two statements in one policy share the Sid %q, which IAM rejects as a "+
					"malformed document", st.Sid),
				Remediation: "this is a bug in the packer's Sid derivation, not a catalog problem; report it",
				Sources:     st.Origins,
			}
		}
		seenSid[st.Sid] = true

		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(st.body)
		sts = append(sts, st.Statement)
	}
	sb.WriteString(`]}`)

	doc := sb.String()
	// Parse what we just built. A packer that emits invalid JSON fails at
	// CreatePolicy, mid-vend, with an account already created — and a
	// hand-assembled document is exactly the kind of thing that gets an escaping
	// bug. Catalog values are attacker-controlled in the threat model, so this is
	// a check on our own rendering, not on AWS.
	var probe any
	if err := json.Unmarshal([]byte(doc), &probe); err != nil {
		return "", nil, &PackError{
			Reason:      fmt.Sprintf("the assembled policy document is not valid JSON: %v", err),
			Remediation: "this is a bug in the packer's renderer, not a catalog problem; report it",
		}
	}
	return doc, sts, nil
}

// renderStatement renders one statement's JSON object.
//
// Rendered through encoding/json rather than by string concatenation, so a
// catalog-supplied action or ARN containing a quote or a backslash cannot break
// out of the document. That is the injection surface the audit ritual names, and
// it is the whole reason this does not build the object with fmt.Sprintf.
func renderStatement(st Statement, opts PackOptions) (string, error) {
	obj := map[string]any{
		"Sid":    st.Sid,
		"Effect": st.Effect,
	}
	// Exactly one of Action and NotAction. A statement with both is meaningless
	// to IAM and a statement with neither denies nothing, so either would be a
	// packer bug rather than a catalog problem.
	switch {
	case st.isAllowlist() && len(st.Action) > 0:
		return "", &PackError{
			Reason: fmt.Sprintf("statement %q carries both Action and NotAction, which IAM cannot "+
				"evaluate", st.Sid),
			Remediation: "this is a bug in the packer; report it",
			Sources:     st.Origins,
		}
	case st.isAllowlist():
		obj["NotAction"] = st.NotAction
	case len(st.Action) > 0:
		obj["Action"] = st.Action
	default:
		return "", &PackError{
			Reason:      fmt.Sprintf("statement %q names no actions, so it denies nothing", st.Sid),
			Remediation: "give the statement an action list in the catalog it comes from",
			Sources:     st.Origins,
		}
	}
	if len(st.Resource) > 0 {
		obj["Resource"] = st.Resource
	} else {
		// An SCP statement must name a resource; "*" is the only sensible default
		// for a Deny that did not narrow it, and it is the strict reading.
		obj["Resource"] = []string{"*"}
	}

	cond, err := renderCondition(st, opts)
	if err != nil {
		return "", err
	}
	if len(cond) > 0 {
		obj["Condition"] = cond
	}

	b, err := marshalNoEscape(obj)
	if err != nil {
		return "", &PackError{
			Reason:      fmt.Sprintf("statement %q could not be rendered: %v", st.Sid, err),
			Remediation: "this is a bug in the packer's renderer; report it",
			Sources:     st.Origins,
		}
	}
	return string(b), nil
}

// renderCondition renders the statement's own condition plus the exemption
// condition, and it is where the exemption list becomes IAM.
//
// An exemption is expressed as ArnNotLike on aws:PrincipalArn: the Deny applies
// to every principal EXCEPT the ones listed. ArnNotLike rather than
// StringNotLike because aws:PrincipalArn is an ARN-typed key and the ARN
// operators normalize case and partition, where the string operators do not — a
// case-mismatched role name under StringNotLike would silently fail to match and
// the exemption would not exist.
//
// Merging into an existing condition is a conflict, not an override: if a catalog
// already constrains aws:PrincipalArn with a negative operator, adding the
// exemption values would loosen the catalog's own constraint. That is a widening,
// so it errors.
//
// # The conflict check reads a SET of operators, and used to read one literal (AUDIT-2)
//
// It compared against `"ArnNotLike"` alone, while behavior.go models six negative
// operators over the same key and IAM accepts all six with an IfExists suffix as
// well. Five spellings walked past it. Neither half of that is a widening — IAM
// ANDs separate condition blocks, so a catalog's StringNotLike and the packer's
// ArnNotLike intersect, and an intersection is narrower than either — which is why
// this is medium and not high, and why the fix is stated in terms of what the check
// is FOR rather than in terms of escalation:
//
//   - The loosening case, which is the original reasoning and applies to every
//     negative operator equally. If a catalog wrote its own exemption list on this
//     key, the exemptions the operator sees rendered are not the list they wrote,
//     and the packer is the only place that can say so.
//   - The case-normalization trap, which is worse and is specific to the string
//     operators. This function refuses to EMIT StringNotLike on aws:PrincipalArn
//     for the reason two paragraphs up — the string operators do not normalize case
//     or partition, so a case-mismatched role name silently matches nothing and the
//     exemption does not exist. A catalog carrying that shape has the bug the packer
//     will not write, and it was passed through in silence.
//
// The positive operators are deliberately NOT conflicts. A catalog's
// ArnLike on aws:PrincipalArn intersected with the packer's ArnNotLike is exactly
// the semantics an exemption wants — applies to matching principals, except the
// listed ones — so erroring there would refuse a correct document.
//
// The operator list is derived from the one behavior.go models rather than written
// out again, because two copies of a security-relevant vocabulary drift and the
// direction they drift in is silent.
func renderCondition(st Statement, opts PackOptions) (map[string]map[string][]string, error) {
	out := map[string]map[string][]string{}
	for op, keys := range st.Condition {
		dup := make(map[string][]string, len(keys))
		for k, vals := range keys {
			dup[k] = sortedUnique(vals)
		}
		out[op] = dup
	}

	if len(st.ExemptPrincipals) == 0 {
		return out, nil
	}

	arns := make([]string, 0, len(st.ExemptPrincipals))
	for _, e := range st.ExemptPrincipals {
		if e.IsAutomationRole() {
			if opts.AutomationRoleARN == "" {
				return nil, &PackError{
					Reason: fmt.Sprintf("statement %q exempts %s but no automation role ARN was supplied",
						st.Sid, artifact.AutomationRolePlaceholder),
					Remediation: "the packer must be given the in-account automation role ARN, which is known " +
						"at vend time; rendering the placeholder literally would produce a condition that " +
						"matches no principal, so the exemption would silently not exist",
					Sources: st.Origins,
				}
			}
			arns = append(arns, opts.AutomationRoleARN)
			continue
		}
		arns = append(arns, e.Principal)
	}
	arns = sortedUnique(arns)

	const op, key = "ArnNotLike", "aws:PrincipalArn"
	// Every operator the statement already carries on this key, not just this one.
	// Sorted, because a map iteration decides which conflict an operator is told
	// about otherwise, and a report that varies between runs on one document is a
	// report an operator cannot act on.
	var clashing []string
	for have := range st.Condition {
		if _, ok := st.Condition[have][key]; ok && isNegativeOperator(have) {
			clashing = append(clashing, have)
		}
	}
	clashing = sortedUnique(clashing)
	if len(clashing) > 0 {
		var detail []string
		for _, have := range clashing {
			detail = append(detail, fmt.Sprintf("%s (%s)", have,
				strings.Join(sortedUnique(st.Condition[have][key]), ", ")))
		}
		return nil, &PackError{
			Reason: fmt.Sprintf("statement %q both exempts principals and already constrains %s with a "+
				"negative operator: %s", st.Sid, key, strings.Join(detail, "; ")),
			Remediation: "express the exemption through exempt_principals or through the condition, not both: " +
				"the packer renders exemptions as " + op + " on " + key + ", and a second negative operator on " +
				"the same key means the exemptions an operator reads in the rendered policy are not the list " +
				"the catalog wrote. If the existing operator is StringNotLike or StringNotEquals, it is also " +
				"the case-sensitivity bug the packer refuses to emit — those operators do not normalize an " +
				"ARN's case or partition, so a mismatched role name exempts nobody",
			Sources: st.Origins,
		}
	}
	if out[op] == nil {
		out[op] = map[string][]string{}
	}
	out[op][key] = arns
	return out, nil
}

// renderable validates the merged set and returns the statements to render.
//
// The allowlists become statements here rather than in Merge, because a
// NotAction/NotResource-shaped Deny is a rendering concern: the type system
// deliberately has no NotAction field (see artifact.SCPStatement) so that a
// catalog author cannot write one, and the packer is the only thing permitted to
// emit that shape.
func (m *Merged) renderable(opts PackOptions) ([]Statement, error) {
	out := append([]Statement(nil), m.Statements...)

	// The global-service exemption list is resolved once, before either allowlist
	// statement is rendered, because both statements carry it and a policy where
	// they carried different lists would deny everything outside their
	// intersection for reasons no reader could see.
	exempt, err := m.exemptGlobalServices()
	if err != nil {
		return nil, err
	}

	if m.RegionAllowlist != nil {
		if len(m.RegionAllowlist.Members) == 0 {
			return nil, &PackError{
				Reason: "the region allowlists of the compiled control sets intersect to nothing, so no " +
					"region would be permitted",
				Remediation: "the control sets disagree about where work may run; compile a set whose regions " +
					"overlap, or override the region allowlist explicitly — an SCP permitting no region denies " +
					"every call in the account, including the ones automat's own baseline makes",
				Sources: m.RegionAllowlist.Sources,
			}
		}
		out = append(out, regionStatement(m.RegionAllowlist, exempt, opts))
	}
	if m.ServiceAllowlist != nil {
		if len(m.ServiceAllowlist.Members) == 0 {
			return nil, &PackError{
				Reason: "the service allowlists of the compiled control sets intersect to nothing, so no " +
					"service would be permitted",
				Remediation: "the control sets disagree about which services may be used; compile a set whose " +
					"service lists overlap, or override the service allowlist explicitly",
				Sources: m.ServiceAllowlist.Sources,
			}
		}
		out = append(out, serviceStatement(m.ServiceAllowlist, exempt, opts))
	}
	return out, nil
}

// exemptGlobalServices resolves the global-service exemption list for the
// allowlist statements, or refuses.
//
// Two refusals, both at PLAN time and both naming which inputs produced the
// state, because the failure they prevent is an account that is created, moved,
// and then unreachable — discovered at apply, after the mutations that cannot be
// undone by trying again.
//
// There is deliberately NO fallback to a built-in list. A fallback is the
// compiled-in list with extra steps: it is unreviewable, uncorrectable without a
// release, and it would silently paper over a control set that forgot to state
// the fact. The list is only needed when something constrains regions or
// services, which is why an artifact may legitimately supply neither.
func (m *Merged) exemptGlobalServices() ([]string, error) {
	if m.RegionAllowlist == nil && m.ServiceAllowlist == nil {
		// Nothing is being restricted, so no exemption is needed and a missing
		// list is not a problem.
		return nil, nil
	}

	if m.RegionDenyExemptServices == nil {
		sources := allowSetSources(m.RegionAllowlist, m.ServiceAllowlist)
		return nil, &PackError{
			Reason: "a compiled control set restricts regions or services, but none of them supplies " +
				"region_deny_exempt_services — the list of globally addressed service namespaces the " +
				"restriction must not cover",
			Remediation: "compile a control set that carries an artifact-level region_deny_exempt_services " +
				"list (automat's own baseline-protection set does, and is attached with every vend). " +
				"automat will not substitute a built-in list: globally addressed services answer on " +
				"endpoints AWS reports as us-east-1, so a restriction that does not exempt them denies " +
				"every IAM, STS, and Organizations call in the account — including the operator's own " +
				"ability to undo it — and a list only this binary knows is a control whose scope cannot " +
				"be reviewed or corrected without a release",
			Sources: sources,
		}
	}

	if len(m.RegionDenyExemptServices.Members) == 0 {
		return nil, &PackError{
			Reason: "the global-service exemption lists of the compiled control sets intersect to nothing, " +
				"so a region or service restriction would cover every service including the globally " +
				"addressed ones",
			Remediation: "the control sets disagree about which services are globally addressed, which is a " +
				"disagreement about how AWS works rather than about policy — reconcile them so their " +
				"region_deny_exempt_services lists overlap. The lists intersect rather than union " +
				"because that is what the rendered policy does: a Deny over NotAction[a:*] alongside a " +
				"Deny over NotAction[b:*] denies everything except what both spare",
			Sources: m.RegionDenyExemptServices.Sources,
		}
	}
	return m.RegionDenyExemptServices.Members, nil
}

// allowSetSources collects the origins of whichever allowlists are constraining,
// so the missing-exemption-list error can name the inputs that made the list
// necessary. Those are the files the operator has to look at: the artifact that
// should have supplied the list is by definition not among the inputs.
func allowSetSources(sets ...*AllowSet) []string {
	var out []string
	for _, s := range sets {
		if s != nil {
			out = append(out, s.Sources...)
		}
	}
	return sortedUnique(out)
}

// regionStatement renders the region allowlist as a NotAction Deny.
//
// NotAction is the correct and documented shape here, and it is the shape
// artifact.SCPStatement deliberately cannot express: a Deny over NotAction denies
// everything it does not name, so two of them concatenate into a deny-all and
// DESIGN §9's safe-concatenation property is lost. The type comment resolves that
// by saying the packer emits this form rather than a catalog author — so the
// field lives on the packer's own statement type, is set in exactly these two
// functions, and is never merged with anything. See Statement.NotAction, and
// TestNoAllowlistStatementIsEverMerged.
//
// Semantics: deny every action EXCEPT the globally addressed services, when the
// requested region is not in the allowlist.
//
// exempt comes from the compiled control sets, not from a list in this package.
// It bricks the account when wrong, which is the argument for it being reviewable
// catalog data — see Merged.RegionDenyExemptServices and exemptGlobalServices,
// which is what guarantees the slice is non-empty by the time it arrives here.
func regionStatement(set *AllowSet, exempt []string, opts PackOptions) Statement {
	st := Statement{
		SCPStatement: artifact.SCPStatement{
			Sid:      "AutomatDenyRegionsOutsideAllowlist",
			Effect:   "Deny",
			Resource: []string{"*"},
			Condition: artifact.Condition{
				"StringNotEquals": {"aws:RequestedRegion": sortedUnique(set.Members)},
			},
		},
		NotAction: serviceWildcards(exempt),
		Origins:   set.Sources,
	}
	if opts.AutomationRoleARN != "" {
		// automat's own automation role is exempt for the same reason it is exempt
		// from baseline protection: it configures the account from wherever the
		// vend runs, and a control that blocks its own installation is not a
		// control. Conditional on the ARN being known, because renderCondition
		// refuses to render the placeholder literally.
		st.ExemptPrincipals = artifact.ExemptPrincipals{{
			Principal: artifact.AutomationRolePlaceholder,
			Reason: "automat's own automation role configures the account and must not be " +
				"region-restricted while doing it",
		}}
	}
	return st
}

// serviceStatement renders the service allowlist as a NotAction Deny.
//
// Deny every action except the allowlisted services' and the global ones'. The
// allowlist is an intersection, so this list only ever shrinks as control sets
// merge — and a shorter NotAction list denies more, which is the monotone
// direction.
func serviceStatement(set *AllowSet, exempt []string, opts PackOptions) Statement {
	st := Statement{
		SCPStatement: artifact.SCPStatement{
			Sid:      "AutomatDenyServicesOutsideAllowlist",
			Effect:   "Deny",
			Resource: []string{"*"},
		},
		NotAction: serviceWildcards(append(append([]string(nil), set.Members...), exempt...)),
		Origins:   set.Sources,
	}
	if opts.AutomationRoleARN != "" {
		st.ExemptPrincipals = artifact.ExemptPrincipals{{
			Principal: artifact.AutomationRolePlaceholder,
			Reason:    "automat's own automation role must be able to call the services it configures",
		}}
	}
	return st
}

// serviceWildcards turns namespaces into "ns:*" action patterns.
func serviceWildcards(namespaces []string) []string {
	out := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		out = append(out, ns+":*")
	}
	return sortedUnique(out)
}

// quotaWarnings reports how much of the quota the pack consumed.
//
// A warning at 80% rather than only at failure: the operator who needs this is
// the one adding a third control set to a working configuration, and they need to
// hear it before the vend that does not fit, not after.
func quotaWarnings(policies []Policy) []string {
	var out []string
	if len(policies) >= AvailablePolicySlots {
		out = append(out, fmt.Sprintf(
			"this control set uses all %d policy slots available to automat at a target "+
				"(%d of %d are reserved for the institutional policy and FullAWSAccess); "+
				"adding another control set will require attaching it at a parent OU",
			AvailablePolicySlots, ReservedPolicySlots, MaxPoliciesPerTarget))
	}
	for _, p := range policies {
		if used := len(p.Document); used*100/MaxPolicySize >= 80 {
			out = append(out, fmt.Sprintf(
				"policy %s is %d of the %d characters AWS allows (%d%%)",
				p.Name, used, MaxPolicySize, used*100/MaxPolicySize))
		}
	}
	return out
}

func allOrigins(sts []Statement) []string {
	var out []string
	for _, st := range sts {
		out = append(out, st.Origins...)
	}
	return sortedUnique(out)
}

// marshalNoEscape marshals without HTML escaping and without the trailing
// newline Encode appends.
//
// SetEscapeHTML(false) because an ARN or action pattern containing & or < would
// otherwise be rendered as &, which IAM compares literally — the condition
// would stop matching and the operator would have no way to see why from the
// policy text.
func marshalNoEscape(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(buf.String(), "\n")), nil
}
