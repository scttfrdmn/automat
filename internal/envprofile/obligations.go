// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

import (
	"fmt"
	"sort"
)

// ObligationFacts is the two-and-a-half facts CheckObligations needs about a
// referenced obligation profile, and deliberately not a model of one.
//
// Obligation profiles are vendored data with no Go types (ROADMAP stage 0: "data and
// schema only, no Go types, no `assess`"), and a struct mirroring the schema here
// would be building exactly what that decision said not to build — plus a second
// definition of a document `assess` will later have its own reading of. The caller
// that already parses the profile fills this in; internal/artifact's
// obligation_profile_test.go reads the same three fields out of raw JSON the same way.
type ObligationFacts struct {
	// ID is the obligation profile id, matching an ObligationRef's.
	ID string
	// ContentSHA256 is the profile's actual content hash, as computed from the
	// document on disk rather than as claimed by the reference.
	ContentSHA256 string
	// RequiresRevisionDetermination is true when ANY of the profile's
	// control_catalogs entries declares `revision_policy: operator-determined`.
	//
	// Any rather than all, because the obligation is unsatisfiable while one catalog's
	// revision is undeclared, and an environment profile carries one determination per
	// obligation. A profile invoking two catalogs where only one is
	// operator-determined still needs the determination made.
	RequiresRevisionDetermination bool
	// UnresolvedSources names the profile's `sources[]` entries whose sha256 is all
	// zeros — a deliberate placeholder for a citation recorded from its published
	// identifier rather than from retrieved bytes. Sorted, empty when the profile's
	// provenance is complete.
	//
	// # Why this is a fact about a profile and not a test fixture (AUDIT-2 F1)
	//
	// docs/policy-caveat.md's standing obligation is that every claim automat RENDERS
	// into a human-facing document traces to a hashed source, and the discipline was
	// held by TestNoUnresolvedHashInARenderableProfile — over a `renderable` map
	// literal declared inside the test function. No renderer could consult it. So the
	// gate was an assertion about a list that existed only while the test ran, and
	// meanwhile `vend` printed `dfars-7012 sha256:<claimed>` on the birth certificate
	// for a profile whose own provenance is sixty-four zeros. Both unvendored profiles
	// were reachable that way.
	//
	// The fact therefore travels with the profile, from the resolver that already read
	// its bytes to whatever renders it. A renderer that prints a citation from a
	// profile with unresolved sources can then say so in the rendered output, which is
	// the only place the caveat is any use — the page explaining it is not what gets
	// forwarded and attached to an agreement.
	UnresolvedSources []string
}

// ProvenanceIsComplete reports whether every source this profile cites has been
// retrieved and hashed.
//
// Named for what a caller wants to know rather than for the field, because the
// question at a rendering site is "may I present this as traced to a source" and the
// answer is not "is a list empty".
func (f ObligationFacts) ProvenanceIsComplete() bool { return len(f.UnresolvedSources) == 0 }

// ObligationResolver returns the facts about one obligation profile by id.
//
// Narrow on purpose, and it may report "unknown" rather than an error, because a
// missing obligation profile and a wrong one are different findings with different
// remediations.
type ObligationResolver interface {
	Obligation(id string) (ObligationFacts, bool)
}

// ObligationSet is the simplest resolver: a map from id to facts.
type ObligationSet map[string]ObligationFacts

// Obligation implements ObligationResolver.
func (s ObligationSet) Obligation(id string) (ObligationFacts, bool) {
	f, ok := s[id]
	return f, ok
}

// CheckObligations enforces the cross-document facts about this profile's obligation
// references, given the obligation profiles it names.
//
// Three checks, all hard errors at PLAN time rather than warnings, and none of them
// expressible in a schema — every one depends on the other document:
//
//  1. Every referenced obligation profile resolves. A reference to a profile automat
//     cannot find is not a weaker claim than a resolved one; it is a claim about a
//     document nobody has read.
//  2. Each reference's content_sha256 is the profile's actual hash. This is the whole
//     reason the field exists: an obligation profile is a reading of policy that
//     moves — notices are superseded, phase-in dates arrive, a class deviation pinning
//     a revision expires — so a reference naming only an id has a subject that can be
//     rewritten underneath it.
//  3. revision_determination is present exactly when the profile declares
//     revision_policy: operator-determined, and absent otherwise. automat ships no
//     default revision in either direction: silently picking one makes a compliance
//     determination on the institution's behalf, and a determination sitting in a
//     pinned profile is a default wearing a different hat — the same refusal the
//     obligation schema states for the `revision` field itself.
//
// Called by `vend` and `verify` at plan time, before anything is created. The failure
// arrives while the plan is still text on a screen, which is the only point at which
// any of these is cheap to fix.
func (p *Profile) CheckObligations(r ObligationResolver) error {
	if len(p.Obligations) == 0 {
		return nil
	}
	if r == nil {
		return fmt.Errorf("cannot check %d obligation reference(s) with no obligation profiles loaded; "+
			"pass the resolver, or the pairing this exists to enforce is silently skipped", len(p.Obligations))
	}
	var probs problems
	for i := range p.Obligations {
		o := &p.Obligations[i]
		path := fmt.Sprintf("obligations[%d]", i)
		facts, ok := r.Obligation(o.ID)
		if !ok {
			probs.add(path+".id", fmt.Sprintf("names obligation profile %s, which is not loaded", safe(o.ID)),
				"check the id against the shipped profiles in catalogs/obligations, or vendor the profile. "+
					"An unresolvable reference is not a weaker claim than a resolved one — it is a claim "+
					"about a document nobody has read")
			continue
		}
		if facts.ContentSHA256 != "" && o.ContentSHA256 != facts.ContentSHA256 {
			probs.add(path+".content_sha256",
				fmt.Sprintf("is %s but obligation profile %s hashes to %s",
					safe(o.ContentSHA256), safe(o.ID), facts.ContentSHA256),
				"re-read the obligation profile and update the reference, having checked what changed in "+
					"it. The hash is what makes this a reference rather than a label: an obligation "+
					"profile is a reading of policy that moves, and a reference by id alone has a subject "+
					"that can be rewritten underneath it")
		}
		switch {
		case facts.RequiresRevisionDetermination && o.RevisionDetermination == nil:
			probs.add(path+".revision_determination",
				fmt.Sprintf("is missing, and obligation profile %s leaves the control catalog revision to "+
					"the operator", safe(o.ID)),
				"record which revision this environment is built against, who determined it, when, and "+
					"on what basis. automat ships no default and will not proceed without one: the "+
					"instrument does not name a revision, institutions have split on it, and a tool that "+
					"picked one would have made a compliance determination on the institution's behalf — "+
					"routing around exactly the person best placed to make it")
		case !facts.RequiresRevisionDetermination && o.RevisionDetermination != nil:
			probs.add(path+".revision_determination",
				fmt.Sprintf("is present, but obligation profile %s pins the control catalog revision itself",
					safe(o.ID)),
				"remove it. There is nothing here for an operator to determine, and a determination "+
					"recorded against a pinned revision is a default wearing a different hat: it renders "+
					"into evidence looking like a decision that was open, and the next reader cannot tell "+
					"whether the pinned revision or this one is the claim")
		}
	}
	if len(probs.list) == 0 {
		return nil
	}
	// Stable order regardless of resolver iteration; the references were already
	// canonicalized by id, but the resolver is caller-supplied and this error is read
	// by a person comparing two runs.
	sort.SliceStable(probs.list, func(i, j int) bool { return probs.list[i].Path < probs.list[j].Path })
	return &ValidationError{Subject: p.subject(), Problems: probs.list}
}
