// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// MergedConfigRule is one AWS Config managed rule, deduped by identifier
// across every control and artifact that bound it, with its parameters
// resolved to one value each via artifact.RuleParameter.Resolve.
//
// DESIGN §9: "Config rules: set-union deduped by rule identifier; overlapping
// parameters resolve by the declared per-parameter order. ... hard error with
// a conflict report demanding explicit resolution." This type is the deduped,
// resolved result; ConflictReport (conflicts.go) is what a caller gets instead
// when resolution failed.
type MergedConfigRule struct {
	// Identifier is the AWS Config managed rule identifier, e.g.
	// "RESTRICTED_INCOMING_TRAFFIC". The dedupe key.
	Identifier string
	// Parameters is the resolved value per parameter name.
	Parameters map[string]artifact.RuleParameter
	// ResourceTypes is the union of every binding's resource type list —
	// informational only (Control.ConfigRules's own doc: nothing evaluates
	// it), so widening it by union rather than intersecting costs nothing
	// and loses no one's intended scope.
	ResourceTypes []string
	// Origins are "artifact-id:control-id" pairs that bound this rule,
	// sorted and deduped — the same provenance convention Statement.Origins
	// uses, for the same reason: a conflict or a report names files, not
	// statement indices.
	Origins []string
}

// addConfigRules folds one control's Config-rule bindings into m, or returns
// a *ConflictReport when a parameter cannot be resolved.
//
// Mirrors addSCP's shape (merge.go): called once per control that carries
// any, origin is "artifact-id:control-id", and the within-artifact merge
// happens through the same accumulator Combine later folds across artifacts —
// so two controls in ONE artifact binding the same rule are deduped here
// exactly as two artifacts binding it are deduped in Combine.
func (m *Merged) addConfigRules(rules []artifact.ConfigRule, artifactID, controlID string, overrides *Overrides) *ConflictReport {
	origin := artifactID + ":" + controlID
	for _, rule := range rules {
		if err := m.addOneConfigRule(rule, origin, overrides); err != nil {
			return err
		}
	}
	return nil
}

func (m *Merged) addOneConfigRule(rule artifact.ConfigRule, origin string, overrides *Overrides) *ConflictReport {
	if m.ConfigRules == nil {
		m.ConfigRules = map[string]*MergedConfigRule{}
	}
	existing, ok := m.ConfigRules[rule.Identifier]
	if !ok {
		params := make(map[string]artifact.RuleParameter, len(rule.Parameters))
		for k, v := range rule.Parameters {
			params[k] = v
		}
		m.ConfigRules[rule.Identifier] = &MergedConfigRule{
			Identifier:    rule.Identifier,
			Parameters:    params,
			ResourceTypes: sortedUnique(rule.ResourceTypes),
			Origins:       []string{origin},
		}
		return nil
	}

	for name, incoming := range rule.Parameters {
		current, has := existing.Parameters[name]
		if !has {
			// Only one side binds this parameter. Keeping it rather than
			// requiring both sides to bind every parameter is the same
			// choice addSCP makes for allowlists: a control that says
			// nothing about a parameter is not a claim that conflicts with
			// one that does.
			existing.Parameters[name] = incoming
			continue
		}
		resolved, err := current.Resolve(incoming, rule.Identifier, name)
		if err != nil {
			if ov, ok := overrides.apply(rule.Identifier, name, current.Order); ok {
				resolved = ov
				m.Warnings = append(m.Warnings, overrideWideningWarnings(rule.Identifier, name,
					current, incoming, resolved, existing.Origins, []string{origin})...)
			} else {
				return conflictReportFrom(err, rule.Identifier, name, existing.Origins, origin)
			}
		}
		existing.Parameters[name] = resolved
	}
	existing.ResourceTypes = sortedUnique(append(existing.ResourceTypes, rule.ResourceTypes...))
	existing.Origins = sortedUnique(append(existing.Origins, origin))
	return nil
}

// combineConfigRules is Combine's Config-rule half: fold b's rules into a
// fresh copy seeded from a, resolving every shared parameter.
//
// A copy rather than a mutation of a, matching Combine's own "neither mutates
// nor aliases its inputs" contract (merge.go) — the property tests call
// Combine repeatedly on the same operands, and an in-place fold would make
// the second call see the first call's output.
//
// The returned warnings are Q22's override-widening disclosure (overrides.go)
// for any conflict this fold resolved via an override; Combine appends them
// to the result's own Warnings the same way it appends everything else this
// fold produces.
func combineConfigRules(a, b *Merged, overrides *Overrides) (map[string]*MergedConfigRule, []string, *ConflictReport) {
	if len(a.ConfigRules) == 0 && len(b.ConfigRules) == 0 {
		return nil, nil, nil
	}
	var warnings []string
	out := map[string]*MergedConfigRule{}
	for id, r := range a.ConfigRules {
		out[id] = cloneConfigRule(r)
	}
	for id, incoming := range b.ConfigRules {
		existing, ok := out[id]
		if !ok {
			out[id] = cloneConfigRule(incoming)
			continue
		}
		for name, incomingParam := range incoming.Parameters {
			currentParam, has := existing.Parameters[name]
			if !has {
				existing.Parameters[name] = incomingParam
				continue
			}
			resolved, err := currentParam.Resolve(incomingParam, id, name)
			if err != nil {
				if ov, ok := overrides.apply(id, name, currentParam.Order); ok {
					resolved = ov
					warnings = append(warnings, overrideWideningWarnings(id, name,
						currentParam, incomingParam, resolved, existing.Origins, incoming.Origins)...)
				} else {
					return nil, nil, conflictReportFrom(err, id, name, existing.Origins, incoming.Origins...)
				}
			}
			existing.Parameters[name] = resolved
		}
		existing.ResourceTypes = sortedUnique(append(existing.ResourceTypes, incoming.ResourceTypes...))
		existing.Origins = sortedUnique(append(existing.Origins, incoming.Origins...))
	}
	return out, warnings, nil
}

func cloneConfigRule(r *MergedConfigRule) *MergedConfigRule {
	params := make(map[string]artifact.RuleParameter, len(r.Parameters))
	for k, v := range r.Parameters {
		params[k] = v
	}
	return &MergedConfigRule{
		Identifier:    r.Identifier,
		Parameters:    params,
		ResourceTypes: append([]string(nil), r.ResourceTypes...),
		Origins:       append([]string(nil), r.Origins...),
	}
}

// SortedConfigRules returns m.ConfigRules as a slice in identifier order, for
// a caller that needs a deterministic sequence — rendering a report,
// producing a golden file — rather than the map itself.
func (m *Merged) SortedConfigRules() []*MergedConfigRule {
	out := make([]*MergedConfigRule, 0, len(m.ConfigRules))
	for _, r := range m.ConfigRules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	return out
}

// reSlotBlockedPorts re-slots a RESTRICTED_INCOMING_TRAFFIC rule's unioned
// port set across its five single-valued blockedPort1..5 parameters.
//
// docs/open-questions.md Q1's carried caveat: blockedPort1-5 are one
// prohibited-port set spread across five slots because
// RESTRICTED_INCOMING_TRAFFIC types each parameter as a single integer, not
// a list. set-union on each slot independently (which addOneConfigRule and
// combineConfigRules both do, because that is the correct per-parameter
// order) produces a resolved *set* of ports per slot whenever two artifacts
// bind that slot to different values — a RuleParameter whose Value is a
// comma-joined list the rule will reject, since the rule reads each
// parameter as a lone integer. This function is the repair: read every
// bound blockedPort* parameter's members, union them across slots (not just
// within one), and re-slot the result one port per parameter — refusing
// rather than silently truncating if more than five distinct ports remain.
//
// Called once, after every artifact-level fold that could have introduced a
// second value into a slot — i.e. by the exported Merge/Combine entry
// points, not by addOneConfigRule/combineConfigRules themselves, since a
// mid-fold rule may still gain more artifacts' worth of ports before the
// final slot assignment is decided.
func reSlotBlockedPorts(rules map[string]*MergedConfigRule) *ConflictReport {
	rule, ok := rules[restrictedIncomingTrafficID]
	if !ok {
		return nil
	}
	var ports []string
	var origins []string
	present := false
	for _, slot := range blockedPortSlots {
		p, ok := rule.Parameters[slot]
		if !ok {
			continue
		}
		present = true
		if p.Order != artifact.OrderSetUnion {
			return &ConflictReport{
				Rule:      restrictedIncomingTrafficID,
				Parameter: slot,
				Reason: fmt.Sprintf("declares order %q, but every %s parameter must be set-union — "+
					"it is one prohibited-port set spread across five slots, and any other order "+
					"cannot be re-slotted", p.Order, restrictedIncomingTrafficID),
				Values:  []string{p.Value},
				Origins: rule.Origins,
			}
		}
		ports = append(ports, p.Members()...)
		origins = append(origins, rule.Origins...)
	}
	if !present {
		return nil
	}
	ports = sortedUnique(ports)
	if len(ports) > len(blockedPortSlots) {
		return &ConflictReport{
			Rule:      restrictedIncomingTrafficID,
			Parameter: strings.Join(blockedPortSlots, ", "),
			Reason: fmt.Sprintf("the unioned prohibited-port set has %d members after combining "+
				"every input, but %s has only %d single-valued slots to hold them "+
				"(blockedPort1..blockedPort%d)", len(ports), restrictedIncomingTrafficID,
				len(blockedPortSlots), len(blockedPortSlots)),
			Values:  ports,
			Origins: sortedUnique(origins),
		}
	}

	next := make(map[string]artifact.RuleParameter, len(rule.Parameters))
	for k, v := range rule.Parameters {
		if !isBlockedPortSlot(k) {
			next[k] = v
		}
	}
	for i, port := range ports {
		next[blockedPortSlots[i]] = artifact.RuleParameter{Value: port, Order: artifact.OrderSetUnion}
	}
	rule.Parameters = next
	return nil
}

// restrictedIncomingTrafficID and blockedPortSlots name the one rule and
// parameter set Q1's caveat applies to. Not derived from the catalog data —
// the caveat is specific to how this one AWS-managed rule types its
// parameters, not a general pattern any set-union parameter set exhibits, so
// generalizing this into a catalog-driven mechanism would build a mechanism
// for a problem with exactly one known instance.
const restrictedIncomingTrafficID = "RESTRICTED_INCOMING_TRAFFIC"

var blockedPortSlots = []string{"blockedPort1", "blockedPort2", "blockedPort3", "blockedPort4", "blockedPort5"}

func isBlockedPortSlot(name string) bool {
	for _, s := range blockedPortSlots {
		if s == name {
			return true
		}
	}
	return false
}
