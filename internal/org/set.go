// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"strings"
)

// PolicySetResult is what reconciling a set of policies against a target
// produced.
type PolicySetResult struct {
	// IDs are the policy ids in the order the specs were given. An entry is empty
	// for a policy a plan would have created.
	IDs []string
	// Actions are every action taken or predicted, in order.
	Actions []Action
	// Orphans are policies automat owns that are attached to the target and are
	// NOT in the spec set. See the note in EnsurePolicySet: automat reports them
	// and cannot remove them.
	Orphans []string
}

// EnsurePolicySet makes every policy in specs exist with the given content and be
// attached to target — DESIGN §7 step 4, for one target.
//
// The specs are the whole compiled artifact's worth of preventive control: the
// control SCPs from the packer, plus the region SCP, the service SCP, and
// baseline-protection. The caller converts a compilesets.Packed into specs; this
// package deliberately does not import the packer, so that the layer which talks
// to Organizations does not depend on the layer that decides what the policies
// should say.
//
// # Ordering within the set
//
// Content first for ALL of them, then attachments. Not cosmetic: the five-per-
// target quota is checked at attach, so interleaving would leave a set half
// attached when the sixth policy is refused — a target carrying two of four
// control policies is a state with no name, whereas a target carrying none is
// simply not yet done. Callers pass baseline-protection last in the slice for the
// same reason the vend orders it last overall (Q13).
//
// # An empty set is a normal outcome
//
// A control set with no preventive statements packs to zero policies —
// cmmc-l1 is exactly that, permanently and by design. This returns an empty
// result rather than treating it as an error, and the vend proceeds: a catalog
// whose controls are all detective still has a recorder, a conformance pack, and
// an evidence manifest to produce.
//
// # Parked, not fatal
//
// Every failure from here reaches the caller as an error for which Parkable
// reports true whenever the organization was left mid-change. The caller must not
// treat that as a reason to exit non-zero and forget the account: by the time
// step 4 runs the account exists, and ROADMAP Phase 2 requires a policy failure
// after a successful create and move to be a resumable parked state.
func (e *Ensurer) EnsurePolicySet(ctx context.Context, target string, specs []PolicySpec) (PolicySetResult, error) {
	res := PolicySetResult{IDs: make([]string, len(specs))}
	if target == "" {
		return res, fmt.Errorf("cannot ensure a service control policy set: no target was given — " +
			"pass the OU the account was moved into")
	}
	if len(specs) == 0 {
		return res, nil
	}
	if err := uniqueNames(specs); err != nil {
		return res, err
	}

	// Content for the whole set first.
	for i, spec := range specs {
		id, act, err := e.EnsurePolicy(ctx, spec)
		if err != nil {
			return res, err
		}
		res.IDs[i] = id
		if act != nil {
			res.Actions = append(res.Actions, *act)
		}
	}

	// Then attachments. A plan reports what it cannot know rather than skipping
	// it: a policy that does not exist yet cannot be looked up on the target, and
	// silently omitting the attachment would make a plan for a first vend look
	// like it attaches nothing.
	for i, spec := range specs {
		id := res.IDs[i]
		if id == "" {
			res.Actions = append(res.Actions, *e.record(Action{
				Verb: VerbUnknown, Kind: "policy attachment", Name: spec.Name, Target: target,
				Detail: "cannot be checked: the policy does not exist yet, so a plan cannot ask whether " +
					"it is attached — it would be, once created",
			}))
			continue
		}
		act, err := e.EnsurePolicyAttachment(ctx, id, spec.Name, target)
		if err != nil {
			return res, err
		}
		if act != nil {
			res.Actions = append(res.Actions, *act)
		}
	}

	orphans, err := e.orphanedPolicies(ctx, target, specs)
	if err == nil {
		res.Orphans = orphans
	}
	// A failed orphan read is not a failed vend. The set is ensured either way,
	// and reporting is the whole purpose of the field.
	return res, nil
}

// orphanedPolicies lists policies automat owns that are attached to target but are
// not in the spec set.
//
// automat reports these and cannot remove them, and both halves are deliberate.
// It cannot remove them because no write interface in internal/awsapi has
// DetachPolicy — TestNoWriteInterfaceCanDestroy holds that — so a narrowed
// artifact leaves the previous vend's policies in force. That is the safe
// direction: the leftover policy is a Deny, so keeping it is strictly more
// restrictive than the operator asked for, whereas detaching it automatically
// would mean a vend against a mistyped artifact id silently widens an OU that was
// compliant this morning. Reporting it means `verify` can say so and a human with
// DetachPolicy can decide.
func (e *Ensurer) orphanedPolicies(ctx context.Context, target string, specs []PolicySpec) ([]string, error) {
	want := make(map[string]bool, len(specs))
	for _, s := range specs {
		want[s.Name] = true
	}
	attached, err := e.attachedPolicies(ctx, target)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range attached {
		if want[p.name] || !strings.HasPrefix(p.name, "automat-") {
			continue
		}
		owned, _, oerr := e.policyOwnership(ctx, p.id)
		if oerr != nil || !owned {
			// Not automat's, or unreadable. Either way not something to report as
			// automat's leftover: a name that merely looks like automat's is
			// somebody else's policy with an unfortunate name, and saying otherwise
			// would invite a human to detach it.
			continue
		}
		out = append(out, fmt.Sprintf("%s (%s)", p.name, p.id))
	}
	return out, nil
}

// uniqueNames refuses a set with a repeated policy name.
//
// A duplicate is a caller bug — two artifacts compiled with the same id, or a
// prefix collision between the control policies and the region policy. It would
// otherwise be invisible: the second EnsurePolicy finds the first one's policy by
// name, decides the content differs, and calls UpdatePolicy, so each vend
// overwrites one document with the other and both runs report a change forever.
// The run-twice criterion would fail with no failing call anywhere.
func uniqueNames(specs []PolicySpec) error {
	seen := make(map[string]int, len(specs))
	for i, s := range specs {
		if j, ok := seen[s.Name]; ok {
			return fmt.Errorf("cannot ensure a service control policy set: entries %d and %d are both "+
				"named %q. Policy names are automat's only handle on its own policies, so two specs with "+
				"one name would overwrite each other's content on every run — check the artifact ids and "+
				"the packer's name prefix", j, i, s.Name)
		}
		seen[s.Name] = i
	}
	return nil
}
