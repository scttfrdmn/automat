// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"fmt"
	"sort"
	"strings"
)

// Narrow applies an environment profile's permitted-behavior boundary to a merged
// control set (DESIGN §7, E4).
//
// # It only ever narrows
//
// The profile's region and service sets are INTERSECTED with the allowlists the
// compiled control sets require — never substituted for them, never added to them.
// That is the union law on the other axis: union of controls, intersection of
// permitted behavior (DESIGN §9). An institution therefore cannot widen its own
// posture by editing an environment profile, which is the whole reason those fields
// are safe to expose in an operator-editable document rather than only in a reviewed
// catalog.
//
// The intersection lives HERE, in the package that renders the resulting Deny and
// holds the can-any-merge-widen property tests, rather than in internal/envprofile
// which owns the document. A second implementation next to the schema would be a
// second answer to "did this widen", and the profile's sets would be checked by
// whichever one the caller happened to reach.
//
// # nil means unconstrained, on both sides
//
// A nil profile set adds no boundary on that axis and leaves the control sets'
// allowlist exactly as it was. That is the same nil-versus-empty distinction
// Merged.RegionAllowlist documents and it is load-bearing for the same reason: a
// document that did not constrain regions must not be read as constraining them to
// nothing.
//
// A non-nil EMPTY profile set is a deny-all, and it does not reach here — the
// schema's minItems and envprofile.Validate both refuse it. If one arrives anyway
// this refuses rather than intersecting, because the caller that produced it skipped
// the validation and an unvalidated deny-all is precisely the input the empty-set
// guard exists for.
//
// # Two surprising-but-correct consequences, both refusals at plan time
//
//   - An intersection that evaluates to nothing is a hard error here, naming which
//     side contributed which members (E5). Never a silently attached deny-all: an
//     empty allowlist denies every call in the account, including the ones automat's
//     own baseline makes, and it would otherwise be discovered after create and move
//     had already succeeded.
//   - Adding a permitted set to a profile can make a compile that used to pack start
//     refusing, because constraining an axis is what obliges some control set to
//     supply region_deny_exempt_services. That refusal is Pack's and it is right:
//     a restriction that does not spare the globally addressed services denies every
//     IAM, STS, and Organizations call in the account, including the operator's own
//     ability to undo it.
func Narrow(m *Merged, opts NarrowOptions) (*Narrowed, error) {
	if m == nil {
		m = &Merged{}
	}
	source := opts.source()

	out := &Narrowed{Merged: &Merged{
		Statements:               make([]Statement, 0, len(m.Statements)),
		RegionAllowlist:          m.RegionAllowlist.clone(),
		ServiceAllowlist:         m.ServiceAllowlist.clone(),
		RegionDenyExemptServices: m.RegionDenyExemptServices.clone(),
	}}
	// Statements are copied rather than shared, for the reason Combine copies them:
	// the caller may still hold the Merged, and a narrowing that reached back into it
	// would make a second call see what the first produced.
	for _, st := range m.Statements {
		out.Merged.Statements = append(out.Merged.Statements, copyStatement(st))
	}

	for _, axis := range []struct {
		name     string
		profile  []string
		existing *AllowSet
		assign   func(*AllowSet)
	}{
		{"region", opts.Regions, m.RegionAllowlist, func(s *AllowSet) { out.Merged.RegionAllowlist = s }},
		{"service", opts.Services, m.ServiceAllowlist, func(s *AllowSet) { out.Merged.ServiceAllowlist = s }},
	} {
		if axis.profile == nil {
			continue
		}
		if len(axis.profile) == 0 {
			return nil, &PackError{
				Stage: narrowStage,
				Reason: fmt.Sprintf("the environment profile's permitted %s set is present but empty, "+
					"which permits no %s at all", axis.name, axis.name),
				Remediation: fmt.Sprintf("omit the permitted.%ss field to add no boundary on that axis, or "+
					"list at least one member. An empty allowlist is not a strict policy but a DENY-ALL: it "+
					"denies every call in the account, including the ones automat's own baseline makes, and "+
					"nothing about the document says so. Reaching this point means the profile was not "+
					"validated before it was compiled — the schema and envprofile.Validate both refuse it",
					axis.name),
				Sources: []string{source},
			}
		}
		narrowed := intersectSets(axis.existing, newAllowSet(axis.profile, source))
		if len(narrowed.Members) == 0 {
			return nil, emptyIntersection(axis.name, axis.existing, axis.profile, source)
		}
		axis.assign(narrowed)
	}

	// m.Warnings carries the union's own disclosures — today, Q22's
	// override-widening warnings (overrides.go) — which narrowing can only
	// ever add to, never resolve, so they are copied forward rather than
	// dropped. Placed before droppedWarnings' own additions so a caller
	// reading the list top to bottom sees "what the union produced" before
	// "what this narrowing step observed."
	out.Warnings = append(append([]string(nil), m.Warnings...), droppedWarnings(m, opts, source)...)
	sortStatements(out.Merged.Statements)
	return out, nil
}

// NarrowOptions carries the environment profile's permitted sets, plus enough
// identity to name it in a conflict report.
//
// Plain slices rather than an envprofile type on purpose. This package must not
// import the one that owns the document: the intersection is about sets, the profile
// is one of two inputs to it, and a Merged narrowed by a hand-built set in a property
// test has to travel the same code path as one narrowed by a document off disk.
type NarrowOptions struct {
	// Regions is the profile's permitted-region set. nil adds no boundary.
	Regions []string
	// Services is the profile's permitted-service-namespace set. nil adds no
	// boundary.
	Services []string
	// ProfileID names the environment profile in conflict reports and in the
	// provenance of the narrowed allowlists. Optional, and its absence costs only
	// specificity in an error message.
	ProfileID string
}

// source is the provenance label for members the profile contributed.
//
// It reads as a document type rather than as a bare id, because the whole point of
// the Q14 rename is that an operator holding three kinds of profile can tell from a
// conflict report which one narrowed their policy.
func (o NarrowOptions) source() string {
	if o.ProfileID == "" {
		return "environment-profile"
	}
	return "environment-profile:" + o.ProfileID
}

// Narrowed is Narrow's output: the narrowed merge, plus what the narrowing observed
// but did not enforce.
type Narrowed struct {
	Merged *Merged
	// Warnings names members the profile asked for that the control sets do not
	// permit. Not an error — the profile can only narrow, so asking for a region the
	// control sets forbid is harmless — but not silent either. An operator who wrote
	// eu-west-1 into a profile and got an account that cannot reach eu-west-1 is owed
	// the sentence explaining why, at plan time, rather than a support ticket after
	// the first deployment fails.
	Warnings []string
}

// emptyIntersection builds the E5 refusal: a hard error at plan time naming which
// inputs produced the emptiness.
//
// Both sides are printed in full. An operator staring at "no region is permitted"
// has two lists and no way to see that they do not overlap, and the whole value of
// this message is that it makes the disjointness visible without their opening two
// files — one of which, the merged control set, is not a file at all.
func emptyIntersection(axis string, existing *AllowSet, profile []string, source string) error {
	want := sortedUnique(profile)
	sources := []string{source}
	var have []string
	if existing != nil {
		have = existing.Members
		sources = append(sources, existing.Sources...)
	}
	return &PackError{
		Stage: narrowStage,
		Reason: fmt.Sprintf("the environment profile permits %ss %s, and the compiled control sets permit "+
			"%ss %s; they have no member in common, so no %s would be permitted",
			axis, quoteList(want), axis, quoteList(have), axis),
		Remediation: fmt.Sprintf("the profile and the control sets disagree about %s: the "+
			"profile can only NARROW what the control sets permit, so every %s it names must be one they "+
			"already allow. Either name a permitted %s from the second list, or compile a control set that "+
			"permits the ones the profile needs. automat refuses rather than attaching the intersection, "+
			"because an SCP permitting no %s denies every call in the account — including the ones "+
			"automat's own baseline makes, and the operator's own ability to undo it — and the account "+
			"would already have been created and moved by the time anyone found out",
			disagreementSubject(axis), axis, axis, axis),
		Sources: sortedUnique(sources),
	}
}

// narrowStage is the first clause of every narrowing refusal.
//
// It names the environment profile, because that is the document the operator has to
// edit and it is the one of the three called a profile that this step reads (Q14).
const narrowStage = "cannot apply the environment profile's permitted sets to the compiled control sets"

// disagreementSubject names what the two documents disagree ABOUT, per axis.
//
// Worth the switch rather than one phrase for both: "where work may run" is true of
// regions and false of services, and an error that describes the wrong axis reads as a
// message written for a different failure — which is how an operator concludes the tool
// is confused and stops reading the paragraph that would have told them the answer.
func disagreementSubject(axis string) string {
	if axis == "region" {
		return "where work may run"
	}
	return "which services may be used"
}

// droppedWarnings reports profile members the control sets do not permit.
func droppedWarnings(m *Merged, opts NarrowOptions, source string) []string {
	var out []string
	for _, axis := range []struct {
		name     string
		profile  []string
		existing *AllowSet
	}{
		{"region", opts.Regions, m.RegionAllowlist},
		{"service", opts.Services, m.ServiceAllowlist},
	} {
		if axis.existing == nil || len(axis.profile) == 0 {
			continue
		}
		permitted := make(map[string]bool, len(axis.existing.Members))
		for _, v := range axis.existing.Members {
			permitted[v] = true
		}
		var dropped []string
		for _, v := range axis.profile {
			if !permitted[v] {
				dropped = append(dropped, v)
			}
		}
		if len(dropped) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s asks to permit %s %s that the compiled control sets do not "+
			"allow: %s. The account will not permit %s — a profile can only narrow what the control sets "+
			"permit, never widen it, so the %s were dropped rather than added.",
			source, plural(len(dropped)), axis.name, quoteList(sortedUnique(dropped)),
			them(len(dropped)), axis.name+plural2(len(dropped))))
	}
	sort.Strings(out)
	return out
}

func plural(n int) string {
	if n == 1 {
		return "a"
	}
	return "several"
}

func plural2(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func them(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// quoteList renders a set for an error message: quoted, comma-separated, and
// explicit about being empty rather than rendering as nothing at all.
//
// "permits regions " with nothing after it reads as a truncated message, and an
// operator who thinks the tool cut off mid-sentence goes looking for a log rather
// than for the two lists that do not overlap.
func quoteList(members []string) string {
	if len(members) == 0 {
		return "nothing (an empty set)"
	}
	out := make([]string, len(members))
	for i, m := range members {
		out[i] = fmt.Sprintf("%q", m)
	}
	return strings.Join(out, ", ")
}
