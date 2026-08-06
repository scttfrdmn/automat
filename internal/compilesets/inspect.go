// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Reading allowlists back off attached policies.
//
// The packer emits region and service restrictions as NotAction Denies, and DESIGN
// §12's `verify` has to answer whether what is attached to an OU still matches the
// environment profile that was compiled for it. That makes emitting only half the
// requirement: a shape automat can render but cannot recover is a shape `verify`
// can only check by string-comparing whole documents, which reports "different"
// for a reordered key and cannot say which region went missing.
//
// So the reader lives beside the renderer, and TestPackedAllowlistsRoundTrip is the
// proof — anything the packer emits, this recovers. It reads documents as AWS
// returns them (DescribePolicy content), not automat's own Statement values, because
// the thing being verified is what is attached and not what was computed: an
// operator can edit an SCP in the console, and that edit is exactly the drift
// `verify` exists to find.
//
// # Multiple documents intersect
//
// A target can carry several SCPs, and the packer splits one control set across
// documents when it does not fit. Two region Denies at one target permit only the
// regions BOTH name, because each denies everything outside its own list — the same
// meet the merger computes, arriving a second time from AWS's evaluation rules. So
// ReadAllowlists takes the whole attached set and intersects, and a caller that
// passed one document of a multi-document pack would get an answer that is wrong in
// the permissive direction.

// AttachedAllowlists is what a set of attached policy documents permits along the
// region and service axes.
//
// nil means the attached policies do not restrict that axis at all. An empty
// non-nil slice means they restrict it to nothing — every call denied — which is
// the bricked account the packer refuses to create and which `verify` must be able
// to report if it finds one anyway. The distinction is the same one Merged draws,
// and collapsing it here would turn "unrestricted" and "denies everything" into the
// same finding.
type AttachedAllowlists struct {
	// Regions is the region allowlist, recovered from the aws:RequestedRegion
	// condition of the region statement(s).
	Regions []string
	// Services is the service allowlist, recovered by subtracting the
	// global-service exemption list from the service statement's NotAction.
	// See ServicesIncludeExemptions for when that subtraction is not possible.
	Services []string
	// ExemptServices is the global-service exemption list the statements carry —
	// the namespaces spared from the restriction. Recovered from a region
	// statement's NotAction, which contains exactly that list.
	ExemptServices []string
	// ServicesIncludeExemptions reports that Services could not be separated from
	// the exemption list, which happens when the attached set restricts services
	// and not regions: the service statement's NotAction is the union of the two,
	// and with no region statement to supply the exemption list there is nothing
	// to subtract.
	//
	// Not an error, because the document is well-formed and a caller holding the
	// environment profile knows the exemption list independently — it can subtract
	// or, better, recompute the expected NotAction and compare. It is a field
	// rather than a silent union because a caller that reported Services to an
	// operator would otherwise show "iam, sts, organizations" as allowlisted
	// services, which nobody put in a profile.
	ServicesIncludeExemptions bool
}

// ReadAllowlists recovers the region and service allowlists a set of attached
// policy documents encodes.
//
// The documents are the JSON content of every SCP attached at one target. Order
// does not matter; the result is their intersection.
//
// It returns an error only when a document cannot be read as a policy at all.
// Everything else — an allowlist that permits nothing, a service statement whose
// NotAction does not spare the exemption list — is reported through the result,
// because those are findings about the attached policies and a caller that got an
// error instead would learn only that something was wrong.
func ReadAllowlists(documents ...string) (*AttachedAllowlists, error) {
	out := &AttachedAllowlists{}
	var sawRegion, sawService bool
	var serviceNotAction []string

	for i, doc := range documents {
		var parsed policyDocument
		if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
			return nil, &PackError{
				Reason: fmt.Sprintf("attached policy %d is not a readable policy document: %v", i+1, err),
				Remediation: "the document attached at this target is not JSON automat can parse, so " +
					"whether it enforces the environment profile cannot be determined; read it in the " +
					"console and either replace it with a compiled policy or record it as an " +
					"institutional policy automat does not manage",
			}
		}
		for _, st := range parsed.Statement {
			if !strings.EqualFold(st.Effect, "Deny") || len(st.NotAction) == 0 {
				// Only a Deny over NotAction is an allowlist. Ordinary Denies are
				// the preventive controls, checked elsewhere against the statements
				// the compile produced.
				continue
			}
			namespaces := namespacesOf(st.NotAction.strings())
			if regions, ok := st.Condition.values("StringNotEquals", "aws:RequestedRegion"); ok {
				out.Regions = intersectOrSeed(out.Regions, regions, sawRegion)
				out.ExemptServices = intersectOrSeed(out.ExemptServices, namespaces, sawRegion)
				sawRegion = true
				continue
			}
			serviceNotAction = intersectOrSeed(serviceNotAction, namespaces, sawService)
			sawService = true
		}
	}

	if !sawService {
		return out, nil
	}
	if !sawRegion {
		out.Services = serviceNotAction
		out.ServicesIncludeExemptions = true
		return out, nil
	}
	out.Services = subtract(serviceNotAction, out.ExemptServices)
	return out, nil
}

// PermitsRegion reports whether the attached policies permit a call in region,
// ignoring the global-service exemption — that is, whether a region-scoped service
// can be used there.
//
// A convenience for `verify`, and a deliberate one: the alternative is every caller
// writing its own membership test against Regions and forgetting that nil means
// unrestricted rather than empty.
func (a *AttachedAllowlists) PermitsRegion(region string) bool {
	if a.Regions == nil {
		return true
	}
	return contains(a.Regions, region)
}

// PermitsService reports whether the attached policies permit calls to a service
// namespace.
//
// True when the namespace is allowlisted or exempt: an exempt namespace is spared
// by every restriction, which is what makes it exempt. When Services could not be
// separated from the exemption list this is still correct, because the union is
// exactly the set of namespaces the statement spares.
func (a *AttachedAllowlists) PermitsService(namespace string) bool {
	if a.Services == nil {
		return true
	}
	return contains(a.Services, namespace) || contains(a.ExemptServices, namespace)
}

// policyDocument is the subset of an SCP document the reader needs.
type policyDocument struct {
	Version   string              `json:"Version"`
	Statement []documentStatement `json:"Statement"`
}

type documentStatement struct {
	Sid       string            `json:"Sid"`
	Effect    string            `json:"Effect"`
	Action    stringOrSlice     `json:"Action"`
	NotAction stringOrSlice     `json:"NotAction"`
	Resource  stringOrSlice     `json:"Resource"`
	Condition documentCondition `json:"Condition"`
}

// stringOrSlice accepts both forms IAM allows for Action, NotAction, Resource and
// condition values.
//
// automat always emits the array form, so this exists for documents automat did
// not write. A console edit that collapsed a one-element array to a string is
// valid IAM and enforced identically; a reader that rejected it would report a
// parse failure on a policy AWS is happily applying, which is the worst kind of
// verify finding — one that is about the tool.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func (s stringOrSlice) strings() []string { return []string(s) }

type documentCondition map[string]map[string]stringOrSlice

func (c documentCondition) values(operator, key string) ([]string, bool) {
	block, ok := c[operator]
	if !ok {
		return nil, false
	}
	v, ok := block[key]
	if !ok {
		return nil, false
	}
	return v.strings(), true
}

// namespacesOf turns "ns:*" action patterns back into namespaces.
//
// A pattern that is not a bare namespace wildcard is dropped rather than
// half-parsed: the packer only ever emits "ns:*", so anything else came from
// somewhere else and guessing at its meaning would report an allowlist entry
// nobody wrote.
func namespacesOf(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		ns, ok := strings.CutSuffix(p, ":*")
		if !ok || ns == "" || strings.Contains(ns, ":") {
			continue
		}
		out = append(out, ns)
	}
	return sortedUnique(out)
}

// intersectOrSeed seeds an accumulator with the first list and intersects
// afterwards — the same nil-is-not-empty discipline intersectSets keeps, needed
// here for the same reason: a second statement must narrow the first, and an
// accumulator that started empty would narrow to nothing.
func intersectOrSeed(acc, next []string, seeded bool) []string {
	if !seeded {
		return keepEmpty(next)
	}
	return intersect(acc, next)
}

// The reader's set operations preserve EMPTY, which is why they do not use
// merge.go's sortedUnique.
//
// sortedUnique returns nil for an empty input, and in the merger that is right: it
// canonicalizes fields where absent and empty are the same document. Here they are
// opposite findings. Two attached policies with disjoint region lists intersect to
// nothing, meaning no region-scoped call can succeed anywhere — and nil means nobody
// restricted regions, which reads as a healthy account. TestTheReaderReportsA
// RestrictionThatPermitsNothing found exactly that conflation on the first run,
// because this file originally reused sortedUnique.
func keepEmpty(in []string) []string {
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

func intersect(a, b []string) []string {
	keep := make(map[string]bool, len(b))
	for _, v := range b {
		keep[v] = true
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if keep[v] {
			out = append(out, v)
		}
	}
	return keepEmpty(out)
}

func subtract(a, b []string) []string {
	drop := make(map[string]bool, len(b))
	for _, v := range b {
		drop[v] = true
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if !drop[v] {
			out = append(out, v)
		}
	}
	return keepEmpty(out)
}
