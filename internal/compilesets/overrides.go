// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Overrides names the human decisions DESIGN §9's Config-rule union defers
// to when it cannot resolve a parameter conflict on its own: "hard error
// with a conflict report demanding explicit resolution (an override file)."
//
// Unpublished (no schema/ entry, per CLAUDE.md rule 6): this is a small,
// operator-local file with no cross-institution provenance requirement,
// unlike an environment profile or a control artifact that travels between
// parties. Go-level validation only.
type Overrides struct {
	Entries []Override `json:"overrides"`

	// applied tracks which (rule, parameter) entries apply actually resolved a
	// real conflict with, for MergeWithOverrides's "an override named nothing"
	// disclosure (unappliedWarnings below). Unexported and not part of the
	// document: it is a bookkeeping detail of one merge run, reset at the top
	// of MergeWithOverrides so a caller that reuses one loaded Overrides value
	// across two independent Merge calls does not carry the first call's
	// bookkeeping into the second.
	applied map[string]bool
}

// Override resolves one rule parameter's conflict to a literal value —
// DESIGN §9's own wording for the remedy ("the value you intend"), not a
// choice between which artifact wins: an operator resolving a conflict
// between three or more artifacts would otherwise have to name one as
// authoritative for a value none of them may individually hold, and a
// literal value is what every conflict report already prints for the
// operator to copy.
type Override struct {
	Rule      string `json:"rule"`
	Parameter string `json:"parameter"`
	Value     string `json:"value"`
}

// LoadOverrides reads and validates an override file.
//
// Unknown fields are rejected, the same discipline every document this
// tool reads applies: an override file with a typo'd key silently resolves
// nothing, and the conflict it was meant to fix still hard-errors — better
// to refuse the file than to let an operator believe they had fixed it.
//
// # Duplicate keys are refused, on the same read path as every other document (AUDIT-4 H1)
//
// artifact.RejectDuplicateKeys runs before the decode, because
// DisallowUnknownFields does not fire on a key that is known twice —
// `"value": "14", "value": "6"` decodes to 6 with no complaint, and the
// operator reviewing the file reads the 14. AUDIT-2 H8 established this
// refusal on every document automat reads; this file is a document automat
// reads, and it is the one whose whole purpose is to state a single value a
// human decided on. Unpublished (no JSON Schema) does not make it exempt: it
// makes the Go read path the only place the refusal can live.
func LoadOverrides(path string) (*Overrides, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, same trust level as --environment-profile
	if err != nil {
		return nil, fmt.Errorf("read override file %s: %w", path, err)
	}
	if err := artifact.RejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("override file %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var o Overrides
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("parse override file %s: %w", path, err)
	}
	if err := o.validate(); err != nil {
		return nil, fmt.Errorf("override file %s: %w", path, err)
	}
	return &o, nil
}

func (o *Overrides) validate() error {
	seen := map[string]bool{}
	for i, e := range o.Entries {
		if e.Rule == "" {
			return fmt.Errorf("overrides[%d]: no rule was given", i)
		}
		if e.Parameter == "" {
			return fmt.Errorf("overrides[%d]: no parameter was given", i)
		}
		if e.Value == "" {
			return fmt.Errorf("overrides[%d]: no value was given — an override with no value would "+
				"resolve the conflict to nothing, which no Config rule accepts", i)
		}
		key := e.Rule + "\x00" + e.Parameter
		if seen[key] {
			return fmt.Errorf("overrides[%d]: %s parameter %s is overridden twice; automat will not "+
				"guess which entry is meant", i, safe(e.Rule), safe(e.Parameter))
		}
		seen[key] = true
	}
	return nil
}

// find returns the override for (rule, parameter), if any.
func (o *Overrides) find(rule, parameter string) (Override, bool) {
	if o == nil {
		return Override{}, false
	}
	for _, e := range o.Entries {
		if e.Rule == rule && e.Parameter == parameter {
			return e, true
		}
	}
	return Override{}, false
}

// apply resolves a conflict using an override, if one names (rule,
// parameter) — returning the override's value verbatim, at the order the
// conflicting parameters themselves declared, since an override states a
// VALUE, not a new order to resolve under.
//
// A caller passes this to resolveParameter as the fallback a genuine
// conflict tries before giving up; see combineConfigRules and
// addOneConfigRule.
//
// Records the (rule, parameter) pair as applied, so unappliedWarnings can
// later report an override entry that never matched a real conflict —
// today that case is a silent no-op with no trace in the compile plan
// output (Q22, docs/open-questions.md).
func (o *Overrides) apply(rule, parameter string, order artifact.ParamOrder) (artifact.RuleParameter, bool) {
	ov, ok := o.find(rule, parameter)
	if !ok {
		return artifact.RuleParameter{}, false
	}
	if o.applied == nil {
		o.applied = map[string]bool{}
	}
	o.applied[rule+"\x00"+parameter] = true
	return artifact.RuleParameter{Value: ov.Value, Order: order}, true
}

// resetApplied clears the applied-entry bookkeeping at the start of a fresh
// merge, so two independent MergeWithOverrides calls sharing one loaded
// *Overrides do not let the first call's applied entries hide the second
// call's unapplied ones.
func (o *Overrides) resetApplied() {
	if o == nil {
		return
	}
	o.applied = nil
}

// unappliedWarnings names every override entry that never matched a real
// conflict during the merge just completed — the Q22 gap: today, an
// override naming a rule/parameter with no conflict at that spot is a
// silent no-op, and the compile plan output does not say an override was
// even applied.
func (o *Overrides) unappliedWarnings() []string {
	if o == nil {
		return nil
	}
	var out []string
	for _, e := range o.Entries {
		if o.applied[e.Rule+"\x00"+e.Parameter] {
			continue
		}
		out = append(out, fmt.Sprintf("override naming %s parameter %s (value %s) was never applied: no "+
			"conflict at that rule and parameter was found to resolve with it. Check the rule and "+
			"parameter names for a typo, or remove the entry if the conflict it was written for no "+
			"longer exists",
			safe(e.Rule), safe(e.Parameter), safe(e.Value)))
	}
	sort.Strings(out)
	return out
}

// overrideWideningWarnings is Q22's disclosure (docs/open-questions.md):
// when an override resolves a genuine Config-rule parameter conflict, this
// reports — without refusing anything — whether the resolved value goes
// beyond what EITHER conflicting side actually permitted.
//
// Q22 settled that the override is trusted verbatim rather than clamped to
// artifact.RuleParameter.Permits: the two conflict shapes that reach this
// path (an exact mismatch, a disjoint set-intersect) both have an empty
// meet, so clamping would convert "resolve a real conflict" into "always
// refuse," defeating the mechanism DESIGN §9 built it for. This function is
// the alternative — visibility instead of a gate — computed from current
// and incoming, the SAME two RuleParameter values the conflict was raised
// against, which is why it can only be called where those two values are
// already in scope: addOneConfigRule and combineConfigRules, immediately
// after overrides.apply succeeds.
//
// Three distinguishable outcomes, per the task that raised this:
//
//   - Scalar orders (exact, min, max): if the resolved value is not
//     numerically comparable under a min/max order (Permits' second return,
//     meaningful, is false), that is reported as its own case — a
//     non-numeric override under a numeric order — rather than folded into
//     "widened", since nothing was actually compared.
//   - Scalar orders, comparable: if neither side permits the resolved
//     value, that is a genuine widening — the case an override exists for —
//     and it is named as such.
//   - Set orders (set-union, set-intersect): each member of the resolved
//     value is classified independently, and only the members permitted by
//     NEITHER side are named — not the whole value — because a value like
//     "ami-1,ami-2,ami-3,ami-4,ami-EVERYTHING" differs from its inputs by
//     exactly one member, and a warning naming the whole value hides the
//     one fact worth reading.
//
// currentOrigins and incomingOrigins name the two conflicting sides in the
// warning text, the same "artifact-id:control-id" provenance every other
// message in this package uses — an operator resolving a widening still
// needs to know which two catalogs disagreed, for the same reason
// ConflictReport.Origins exists.
func overrideWideningWarnings(rule, parameter string, current, incoming, resolved artifact.RuleParameter,
	currentOrigins, incomingOrigins []string) []string {
	curDesc := "the current binding (from " + describeOrigins(currentOrigins) + ")"
	incDesc := "the incoming binding (from " + describeOrigins(incomingOrigins) + ")"

	if resolved.Order.IsSet() {
		var neither []string
		for _, member := range resolved.Members() {
			curPermitted, _ := current.Permits(member)
			incPermitted, _ := incoming.Permits(member)
			if !curPermitted && !incPermitted {
				neither = append(neither, member)
			}
		}
		if len(neither) == 0 {
			return nil
		}
		return []string{fmt.Sprintf("override for %s parameter %s resolves to %s, which includes %s that "+
			"neither %s nor %s permits: %s. DESIGN §9's monotonicity does not hold for %s on their "+
			"own — the override is applied anyway, because resolving a genuine conflict with a value "+
			"neither side individually held is exactly what an override is for (docs/open-questions.md Q22)",
			safe(rule), safe(parameter), safe(resolved.Value), plural2Members(len(neither)),
			curDesc, incDesc, quoteList(neither), plural2Members(len(neither)))}
	}

	curPermitted, curMeaningful := current.Permits(resolved.Value)
	incPermitted, incMeaningful := incoming.Permits(resolved.Value)
	if !curMeaningful || !incMeaningful {
		return []string{fmt.Sprintf("override for %s parameter %s resolves to %s under order %s, but "+
			"whether it widens the parameter could not be checked: the order compares values "+
			"numerically, and %s or %s holds a value that is not a number. The override is applied "+
			"anyway, unchecked (docs/open-questions.md Q22)",
			safe(rule), safe(parameter), safe(resolved.Value), safe(string(resolved.Order)), curDesc, incDesc)}
	}
	if curPermitted || incPermitted {
		return nil
	}
	return []string{fmt.Sprintf("override for %s parameter %s resolves to %s, which neither %s nor %s "+
		"permits. DESIGN §9's monotonicity does not hold for this value on its own — the override is "+
		"applied anyway, because resolving a genuine conflict with a value neither side individually "+
		"held is exactly what an override is for (docs/open-questions.md Q22)",
		safe(rule), safe(parameter), safe(resolved.Value), curDesc, incDesc)}
}

// describeOrigins renders an origin list for overrideWideningWarnings, quoted
// the same way every other catalog-supplied value in this package's error
// messages is (conflicts.go's safe convention) — an origin is
// "artifact-id:control-id", both attacker-controlled in the threat model.
func describeOrigins(origins []string) string {
	if len(origins) == 0 {
		return "an unrecorded origin"
	}
	quoted := make([]string, len(origins))
	for i, o := range origins {
		quoted[i] = safe(o)
	}
	return strings.Join(quoted, ", ")
}

// plural2Members reads naturally in overrideWideningWarnings' set-order
// sentence, which names a specific list right after this word and would
// read oddly with narrow.go's plural/plural2 helpers (those are built for
// "a region"/"several regions", not "members").
func plural2Members(n int) string {
	if n == 1 {
		return "a member"
	}
	return "members"
}
