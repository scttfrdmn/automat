// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"fmt"
	"sort"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// DESIGN §9: "Procedural controls: dedupe via crosswalk so one practice is
// attested once, not once per framework ID; the stub lists all satisfied
// IDs."
//
// # No consumer yet, and that is stated rather than hidden
//
// DedupeAttestations groups controls into practices; it does not render an
// attestation stub. Nothing in this binary does — stub generation is part of
// DESIGN §7 step 5's in-child baseline work (internal/baseline), which does
// not exist (docs/cli-surface.md D3). cmd/automat/vend.go's own
// attestationIDs lists every procedural control's id, undeduped, for a
// disclosure sentence ("attestation stubs are not performed") that only
// needs to know whether any exist — building the dedupe grouping into that
// disclosure would claim a stub this build cannot produce. This function
// exists so the grouping logic is written, tested, and ready for whichever
// later change adds the renderer, rather than being designed for the first
// time under the pressure of that change.

// DedupedAttestation is one practice: every control, across every merged
// artifact, that a shared crosswalk entry ties together.
type DedupedAttestation struct {
	// ControlIDs are every control's id that belongs to this practice,
	// sorted. DESIGN §9: "the stub lists all satisfied IDs" — this is that
	// list, one hop before a stub exists to hold it.
	ControlIDs []string
	// Crosswalk is the union of every grouped control's own crosswalk map.
	// Two controls naming the same framework key are the reason they are in
	// one group at all, so this can only disagree if the SAME control cites
	// two different ids for one framework — which dedupeAttestationGroups
	// refuses rather than picking one (see its doc comment).
	Crosswalk map[string]string
	// Template, Frequency, and Guidance are the attestation's own fields,
	// required to agree across every control in the group — see
	// dedupeAttestationGroups for why disagreement is refused rather than
	// resolved.
	Template  string
	Frequency string
	Guidance  string
	// Origins are "artifact-id:control-id" pairs, sorted and deduped — the
	// same provenance convention Statement.Origins and MergedConfigRule.
	// Origins use.
	Origins []string
}

// AttestationConflict reports that two controls this practice grouping
// would otherwise merge disagree about what the merged attestation should
// say — CLAUDE.md rule 7's remediation, and DESIGN §9's "never guess"
// discipline applied to the procedural half the way ConflictReport applies
// it to the Config-rule half.
type AttestationConflict struct {
	ControlA, ControlB string
	Field              string
	ValueA, ValueB     string
}

func (c *AttestationConflict) Error() string {
	return fmt.Sprintf("controls %s and %s share a crosswalk entry, so they are one practice under "+
		"DESIGN §9's dedupe rule, but their %s disagrees (%s vs %s). automat will not guess which "+
		"is meant; correct one of the two catalogs so the attestation they share states one thing",
		safe(c.ControlA), safe(c.ControlB), safe(c.Field), safe(c.ValueA), safe(c.ValueB))
}

// DedupeAttestations groups every procedural control across artifacts into
// practices, transitively: control A and control B are one practice if they
// share any (framework, id) crosswalk pair, and control B and control C are
// one practice if THEY share a pair — even if A and C share none directly.
// That transitivity is what "dedupe" requires: a campus baseline citing
// 800-171r2 3.1.1 and a CMMC catalog citing the same id under a different
// framework key are the same practice by construction, and a third catalog
// bridging to a fourth framework through either one is still the same
// practice.
//
// Controls with no artifact.EnforcementProcedural are ignored entirely —
// this is the procedural half only, mirroring FromArtifact's addSCP/
// addConfigRules split by enforcement concern.
//
// Returns an error only when two controls sharing a crosswalk entry
// disagree about the attestation's Template, Frequency, or Guidance — see
// AttestationConflict. This is stricter than the Config-rule half's
// per-parameter orders: an attestation has no declared partial order to
// resolve a disagreement by, so any disagreement within one group is a
// conflict, full stop.
func DedupeAttestations(artifacts ...*artifact.Artifact) ([]DedupedAttestation, error) {
	nodes := collectProceduralControls(artifacts)
	if len(nodes) == 0 {
		return nil, nil
	}

	groups := groupByCrosswalk(nodes)

	out := make([]DedupedAttestation, 0, len(groups))
	for _, group := range groups {
		d, err := mergeGroup(group)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlIDs[0] < out[j].ControlIDs[0] })
	return out, nil
}

// controlNode is one procedural control, with the provenance and crosswalk
// this function needs — narrower than artifact.Control so the grouping
// logic below is not tempted to reach into fields it has no business
// reading (an SCP fragment, say).
type controlNode struct {
	origin    string
	crosswalk map[string]string
	att       *artifact.Attestation
}

func collectProceduralControls(artifacts []*artifact.Artifact) []controlNode {
	var out []controlNode
	for _, a := range artifacts {
		if a == nil {
			continue
		}
		for _, c := range a.Controls {
			if !c.Enforces(artifact.EnforcementProcedural) || c.Attestation == nil {
				continue
			}
			out = append(out, controlNode{
				origin:    a.Meta.ID + ":" + c.ID,
				crosswalk: c.Crosswalk,
				att:       c.Attestation,
			})
		}
	}
	return out
}

// groupByCrosswalk partitions nodes into connected components under "shares
// a (framework, id) crosswalk pair" — a union-find over node indices, keyed
// by every crosswalk pair each node carries.
func groupByCrosswalk(nodes []controlNode) [][]controlNode {
	parent := make([]int, len(nodes))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			i = parent[i]
		}
		return i
	}
	union := func(i, j int) {
		ri, rj := find(i), find(j)
		if ri != rj {
			parent[ri] = rj
		}
	}

	byPair := map[string][]int{}
	for i, n := range nodes {
		for framework, id := range n.crosswalk {
			key := framework + "\x00" + id
			byPair[key] = append(byPair[key], i)
		}
	}
	for _, indices := range byPair {
		for k := 1; k < len(indices); k++ {
			union(indices[0], indices[k])
		}
	}

	byRoot := map[int][]controlNode{}
	for i, n := range nodes {
		r := find(i)
		byRoot[r] = append(byRoot[r], n)
	}
	groups := make([][]controlNode, 0, len(byRoot))
	for _, g := range byRoot {
		groups = append(groups, g)
	}
	return groups
}

// mergeGroup combines one connected component into a DedupedAttestation,
// refusing if the group disagrees about the attestation itself.
func mergeGroup(group []controlNode) (DedupedAttestation, error) {
	sort.Slice(group, func(i, j int) bool { return group[i].origin < group[j].origin })

	first := group[0]
	d := DedupedAttestation{
		Crosswalk: map[string]string{},
		Template:  first.att.Template,
		Frequency: first.att.Frequency,
		Guidance:  first.att.Guidance,
	}
	for k, v := range first.crosswalk {
		d.Crosswalk[k] = v
	}

	for _, n := range group[1:] {
		if n.att.Template != d.Template {
			return DedupedAttestation{}, &AttestationConflict{
				ControlA: first.origin, ControlB: n.origin, Field: "template",
				ValueA: d.Template, ValueB: n.att.Template,
			}
		}
		if n.att.Frequency != d.Frequency {
			return DedupedAttestation{}, &AttestationConflict{
				ControlA: first.origin, ControlB: n.origin, Field: "frequency",
				ValueA: d.Frequency, ValueB: n.att.Frequency,
			}
		}
		if n.att.Guidance != d.Guidance {
			return DedupedAttestation{}, &AttestationConflict{
				ControlA: first.origin, ControlB: n.origin, Field: "guidance",
				ValueA: d.Guidance, ValueB: n.att.Guidance,
			}
		}
		for k, v := range n.crosswalk {
			if existing, ok := d.Crosswalk[k]; ok && existing != v {
				return DedupedAttestation{}, &AttestationConflict{
					ControlA: first.origin, ControlB: n.origin,
					Field:  "crosswalk[" + k + "]",
					ValueA: existing, ValueB: v,
				}
			}
			d.Crosswalk[k] = v
		}
	}

	ids := make(map[string]bool, len(group))
	origins := make([]string, 0, len(group))
	for _, n := range group {
		origins = append(origins, n.origin)
		// origin is "artifact-id:control-id"; the control id is what
		// ControlIDs names, per DESIGN §9's "the stub lists all satisfied
		// IDs" — a control id, not an artifact-qualified one, since that is
		// the handle the attestation vocabulary already uses
		// (cmd/automat/vend.go's own attestationIDs).
		if idx := lastColon(n.origin); idx >= 0 {
			ids[n.origin[idx+1:]] = true
		}
	}
	for id := range ids {
		d.ControlIDs = append(d.ControlIDs, id)
	}
	sort.Strings(d.ControlIDs)
	d.Origins = sortedUnique(origins)
	return d, nil
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}
