// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Narrowing tests: the environment profile's permitted sets applied to a merge.
//
// The claim under test is E4's, and it is one-directional: narrowing may only ever
// narrow. Every property here is a can-any-merge-widen property with the REGION AND
// SERVICE SETS as subjects, which is what E4 asked for by name — the existing
// properties have the statements as subjects and Combine as the operation, and
// neither sees an operator-editable document reaching the same fields from outside a
// reviewed catalog.
//
// That distinction is the whole reason these are separate tests rather than another
// case in drawMerged. A control set is compiled, hashed, and reviewed. An environment
// profile is hand-written by the operator running the vend. If the profile could
// widen, every review of every catalog would be advisory.

func TestNarrowIntersectsRatherThanReplacing(t *testing.T) {
	for _, tc := range []struct {
		name         string
		merged       *Merged
		opts         NarrowOptions
		wantRegions  []string
		wantServices []string
	}{
		{
			name: "profile narrows a control set's regions",
			merged: withGlobalExemptions(&Merged{
				RegionAllowlist: newAllowSet([]string{"us-east-1", "us-east-2", "us-west-2"}, "800-171r2:3.1.3"),
			}),
			opts:        NarrowOptions{Regions: []string{"us-east-1", "us-west-2"}},
			wantRegions: []string{"us-east-1", "us-west-2"},
		},
		{
			name: "a profile region the control sets forbid is dropped, not added",
			merged: withGlobalExemptions(&Merged{
				RegionAllowlist: newAllowSet([]string{"us-east-1"}, "800-171r2:3.1.3"),
			}),
			// eu-west-1 is the widening attempt: the operator asks for a region the
			// compiled set does not permit, and gets an account that does not reach it.
			opts:        NarrowOptions{Regions: []string{"us-east-1", "eu-west-1"}},
			wantRegions: []string{"us-east-1"},
		},
		{
			name:   "a profile constrains an axis no control set constrained",
			merged: withGlobalExemptions(&Merged{}),
			// nil control-set allowlist is the identity, so the profile's set stands
			// alone. This is the ordinary case for services: most catalogs say nothing
			// about them, and the institution's own boundary is the only one there is.
			opts:         NarrowOptions{Services: []string{"s3", "batch"}},
			wantServices: []string{"batch", "s3"},
		},
		{
			name: "an absent profile set leaves the control sets' allowlist alone",
			merged: withGlobalExemptions(&Merged{
				RegionAllowlist: newAllowSet([]string{"us-east-1", "us-west-2"}, "800-171r2:3.1.3"),
			}),
			opts:        NarrowOptions{},
			wantRegions: []string{"us-east-1", "us-west-2"},
		},
		{
			name:         "both axes at once",
			merged:       withGlobalExemptions(&Merged{ServiceAllowlist: newAllowSet([]string{"s3", "ec2", "batch"}, "cmmc-l1:AC.L1-3.1.1")}),
			opts:         NarrowOptions{Regions: []string{"us-west-2"}, Services: []string{"s3", "batch"}},
			wantRegions:  []string{"us-west-2"},
			wantServices: []string{"batch", "s3"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Narrow(tc.merged, tc.opts)
			if err != nil {
				t.Fatalf("Narrow: %v", err)
			}
			assertMembers(t, "region", got.Merged.RegionAllowlist, tc.wantRegions)
			assertMembers(t, "service", got.Merged.ServiceAllowlist, tc.wantServices)
		})
	}
}

func assertMembers(t *testing.T, axis string, got *AllowSet, want []string) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("%s allowlist is %v; expected it to stay unconstrained (nil), and nil versus empty "+
				"is the difference between no boundary and a deny-all", axis, got.Members)
		}
		return
	}
	if got == nil {
		t.Fatalf("%s allowlist is unconstrained; expected %v", axis, want)
	}
	if strings.Join(sortedUnique(got.Members), ",") != strings.Join(want, ",") {
		t.Errorf("%s allowlist is %v, want %v", axis, got.Members, want)
	}
}

// TestNarrowNamesTheProfileInTheProvenance.
//
// Sources exist for the error message (see AllowSet), and after a narrowing the
// operator's question when a region goes missing is which of the three documents
// called a profile took it away. A source list naming only catalogs sends them to
// read every catalog for a constraint that is not in any of them.
func TestNarrowNamesTheProfileInTheProvenance(t *testing.T) {
	got, err := Narrow(
		withGlobalExemptions(&Merged{
			RegionAllowlist: newAllowSet([]string{"us-east-1", "us-west-2"}, "800-171r2:3.1.3"),
		}),
		NarrowOptions{Regions: []string{"us-west-2"}, ProfileID: "clinical-genomics-l3"},
	)
	if err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	sources := strings.Join(got.Merged.RegionAllowlist.Sources, " ")
	for _, want := range []string{"800-171r2:3.1.3", "environment-profile:clinical-genomics-l3"} {
		if !strings.Contains(sources, want) {
			t.Errorf("the narrowed allowlist's provenance is %q and does not name %q; an operator asking "+
				"why a region is missing cannot tell whether a catalog or the environment profile removed it",
				sources, want)
		}
	}
	// The document TYPE and not only the id: three unrelated documents are called
	// profiles (Q14), and a bare id in a conflict report is ambiguous to exactly the
	// auditor it exists for.
	if !strings.Contains(sources, "environment-profile:") {
		t.Error("the provenance names the profile by id alone; it must say which of the three document " +
			"types called a profile the constraint came from")
	}
}

// TestNarrowRefusesADisjointIntersection is E5 at the narrowing layer.
//
// The refusal is the product here. The account has not been created, the operator has
// a profile and a compiled set that share no region, and the alternative to this error
// is an SCP permitting no region at all — attached after create and move have already
// succeeded, denying every call including the ones automat's own baseline makes and
// the operator's own ability to undo it.
func TestNarrowRefusesADisjointIntersection(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts NarrowOptions
		// mustName is what the message has to contain for it to be worth returning:
		// both sides' members, so the disjointness is visible without opening two
		// files — one of which is not a file.
		mustName []string
	}{
		{
			name:     "regions",
			opts:     NarrowOptions{Regions: []string{"eu-west-1"}, ProfileID: "clinical-genomics-l3"},
			mustName: []string{"eu-west-1", "us-east-1", "us-west-2", "environment-profile:clinical-genomics-l3", "800-171r2:3.1.3"},
		},
		{
			name:     "services",
			opts:     NarrowOptions{Services: []string{"sagemaker"}, ProfileID: "clinical-genomics-l3"},
			mustName: []string{"sagemaker", "s3", "batch", "environment-profile:clinical-genomics-l3", "cmmc-l1:AC.L1-3.1.1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := withGlobalExemptions(&Merged{
				RegionAllowlist:  newAllowSet([]string{"us-east-1", "us-west-2"}, "800-171r2:3.1.3"),
				ServiceAllowlist: newAllowSet([]string{"s3", "batch"}, "cmmc-l1:AC.L1-3.1.1"),
			})
			got, err := Narrow(m, tc.opts)
			if err == nil {
				t.Fatalf("a disjoint %s intersection packed instead of refusing; the account would have been "+
					"created and moved before anyone found out it permits no %s at all", tc.name, tc.name)
			}
			if got != nil {
				t.Error("Narrow returned a result alongside the refusal; a caller that ignored the error " +
					"would attach a deny-all")
			}
			var pe *PackError
			if !errors.As(err, &pe) {
				t.Fatalf("the refusal is %T, not a *PackError with remediation text (CLAUDE.md rule 7): %v", err, err)
			}
			for _, want := range tc.mustName {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %q, so the operator cannot see which inputs produced "+
						"the emptiness (E5):\n%s", want, err)
				}
			}
			if !strings.Contains(strings.ToLower(pe.Remediation), "narrow") {
				t.Errorf("the remediation does not say the profile can only narrow, which is the fact that "+
					"tells the operator to change the profile rather than the catalog: %q", pe.Remediation)
			}
		})
	}
}

// TestNarrowRefusesAPresentButEmptyProfileSet.
//
// The deny-all a validated profile cannot carry. Both the schema's minItems and
// envprofile.Validate refuse it, so reaching here means the caller skipped
// validation — and an unvalidated deny-all is precisely the input the empty-set guard
// exists for. Intersecting it would produce an empty allowlist and the SAME refusal
// one layer down, with a message about the control sets disagreeing when nothing
// disagreed.
func TestNarrowRefusesAPresentButEmptyProfileSet(t *testing.T) {
	for _, axis := range []struct {
		name string
		opts NarrowOptions
	}{
		{"regions", NarrowOptions{Regions: []string{}}},
		{"services", NarrowOptions{Services: []string{}}},
	} {
		t.Run(axis.name, func(t *testing.T) {
			m := withGlobalExemptions(&Merged{
				RegionAllowlist:  newAllowSet([]string{"us-east-1"}, "800-171r2:3.1.3"),
				ServiceAllowlist: newAllowSet([]string{"s3"}, "cmmc-l1:AC.L1-3.1.1"),
			})
			_, err := Narrow(m, axis.opts)
			if err == nil {
				t.Fatal("a present-but-empty permitted set was intersected instead of refused; the result " +
					"denies every call in the account and nothing about the document says so")
			}
			// It must be reported as a broken document, not as a disagreement. The
			// remediations are different: one says fix the profile, the other says
			// reconcile the profile with the catalogs.
			if !strings.Contains(err.Error(), "present but empty") {
				t.Errorf("the refusal does not identify the input as present-but-empty, so the operator is "+
					"sent to reconcile two documents when only one is wrong:\n%v", err)
			}
			if !strings.Contains(err.Error(), "DENY-ALL") {
				t.Errorf("the refusal does not say what an empty allowlist does:\n%v", err)
			}
		})
	}
}

// TestNarrowWarnsAboutDroppedMembersRatherThanSilentlyDroppingThem.
//
// Asking for a region the control sets forbid is not an error — the profile can only
// narrow, so the request is harmless — but it is also not what the operator asked for.
// They wrote eu-west-1 into a document and will get an account that cannot reach it,
// and the sentence explaining why is owed at plan time rather than after the first
// deployment fails.
func TestNarrowWarnsAboutDroppedMembersRatherThanSilentlyDroppingThem(t *testing.T) {
	got, err := Narrow(
		withGlobalExemptions(&Merged{
			RegionAllowlist:  newAllowSet([]string{"us-east-1"}, "800-171r2:3.1.3"),
			ServiceAllowlist: newAllowSet([]string{"s3"}, "cmmc-l1:AC.L1-3.1.1"),
		}),
		NarrowOptions{
			Regions:   []string{"us-east-1", "eu-west-1"},
			Services:  []string{"s3", "sagemaker"},
			ProfileID: "clinical-genomics-l3",
		},
	)
	if err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	if len(got.Warnings) != 2 {
		t.Fatalf("expected one warning per axis, got %d: %v", len(got.Warnings), got.Warnings)
	}
	all := strings.Join(got.Warnings, "\n")
	for _, want := range []string{"eu-west-1", "sagemaker", "clinical-genomics-l3", "narrow"} {
		if !strings.Contains(all, want) {
			t.Errorf("the warnings do not mention %q:\n%s", want, all)
		}
	}
	// And the members really are gone: a warning that accompanied a widening would
	// be worse than no warning.
	if contains(got.Merged.RegionAllowlist.Members, "eu-west-1") {
		t.Error("the narrowed allowlist permits eu-west-1, which the control sets forbid — the warning " +
			"described a drop that did not happen")
	}
}

// TestNarrowWarnsOnlyWhenTheControlSetsConstrainedTheAxis.
//
// A profile constraining an axis nothing else constrained has dropped nothing, and a
// warning there would train the operator to ignore the ones that matter. This is the
// nil-is-the-identity rule showing up in the reporting.
func TestNarrowWarnsOnlyWhenTheControlSetsConstrainedTheAxis(t *testing.T) {
	got, err := Narrow(withGlobalExemptions(&Merged{}), NarrowOptions{
		Regions:  []string{"us-east-1", "eu-west-1"},
		Services: []string{"s3"},
	})
	if err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	if len(got.Warnings) != 0 {
		t.Errorf("nothing was dropped — no control set constrained either axis — but Narrow warned anyway: %v",
			got.Warnings)
	}
}

// TestNarrowDoesNotMutateItsOperand.
//
// A narrowing that wrote through the Merged would make the SECOND vend from one
// compile stricter than the first, and `compile` caches a Merged across the vends of
// a batch. The same aliasing hazard Combine has, arriving from the other direction.
func TestNarrowDoesNotMutateItsOperand(t *testing.T) {
	m := withGlobalExemptions(&Merged{
		RegionAllowlist:  newAllowSet([]string{"us-east-1", "us-west-2"}, "800-171r2:3.1.3"),
		ServiceAllowlist: newAllowSet([]string{"s3", "batch"}, "cmmc-l1:AC.L1-3.1.1"),
		Statements:       narrowFixtureStatements(),
	})
	before := mergedKey(m)

	if _, err := Narrow(m, NarrowOptions{Regions: []string{"us-west-2"}, Services: []string{"s3"}}); err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	if mergedKey(m) != before {
		t.Error("Narrow mutated the Merged it was given; the next vend from the same compile would enforce " +
			"something narrower than the first")
	}
}

// narrowFixtureStatements is a fixed statement pair for the mutation test — enough
// shape, including an exemption list, that a shared slice would show up as a changed
// key.
func narrowFixtureStatements() []Statement {
	return mergeStatements([]Statement{
		{
			SCPStatement: artifact.SCPStatement{
				Sid:      "ProtectRecorder",
				Effect:   "Deny",
				Action:   []string{"config:StopConfigurationRecorder"},
				Resource: []string{"*"},
				ExemptPrincipals: artifact.ExemptPrincipals{
					{Principal: testAutomationRole, Reason: "automat establishes the recorder"},
				},
			},
			Origins: []string{"800-171r2:3.3.1"},
		},
		{
			SCPStatement: artifact.SCPStatement{
				Sid:      "ProtectTrail",
				Effect:   "Deny",
				Action:   []string{"cloudtrail:StopLogging"},
				Resource: []string{"*"},
			},
			Origins: []string{"cmmc-l1:AU.L1-3.3.1"},
		},
	})
}

// ---------------------------------------------------------------------------
// Properties: narrowing cannot widen
// ---------------------------------------------------------------------------

// TestNarrowingNeverWidensTheAllowlists is E4 as a property, at the set level.
//
// The claim: for each axis, the narrowed allowlist permits nothing the control sets'
// allowlist did not permit. Equality is not required and would be wrong to require —
// narrowing is allowed to remove members, that is its name — so the property is
// subset in one direction only.
//
// The empty profile set is excluded because Narrow refuses it rather than intersecting,
// and TestNarrowRefusesAPresentButEmptyProfileSet covers that path with an assertion
// about the message. Including it here would make this property mostly early returns.
func TestNarrowingNeverWidensTheAllowlists(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := drawRenderable(rt, "m")
		opts := drawNarrowOptions(rt, "p")

		got, err := Narrow(m, opts)
		if err != nil {
			// A disjoint intersection. Nothing is attached, so nothing widened.
			return
		}
		for _, axis := range []struct {
			name    string
			before  *AllowSet
			after   *AllowSet
			profile []string
		}{
			{"region", m.RegionAllowlist, got.Merged.RegionAllowlist, opts.Regions},
			{"service", m.ServiceAllowlist, got.Merged.ServiceAllowlist, opts.Services},
		} {
			if axis.before == nil {
				// Nothing to widen relative to. The profile may constrain freely here:
				// a boundary where there was none is narrower, not wider.
				continue
			}
			permitted := map[string]bool{}
			for _, v := range axis.before.Members {
				permitted[v] = true
			}
			if axis.after == nil {
				rt.Fatalf("narrowing LOST the %s allowlist: the control sets constrained it and the "+
					"narrowed merge does not. A dropped boundary is the widest possible widening",
					axis.name)
			}
			for _, v := range axis.after.Members {
				if !permitted[v] {
					rt.Fatalf("narrowing WIDENED the %s allowlist: it permits %q, which the control sets "+
						"forbid (control sets permit %v, profile asked for %v, result %v). An environment "+
						"profile is operator-written and unreviewed; if it can widen, every catalog review "+
						"is advisory",
						axis.name, v, axis.before.Members, axis.profile, axis.after.Members)
				}
			}
		}
	})
}

// TestNarrowingNeverWidensTheRenderedPolicy is the same claim with the ATTACHED
// DOCUMENT as the subject, which is what E4 asked for: the region and service sets as
// subjects of the can-any-merge-widen coverage, not just the statements.
//
// Separate from the set-level property above because intersecting the members
// correctly and then rendering a policy that permits more than the unnarrowed one
// would satisfy that property and fail this one — a condition operator changed, a
// NotAction list assembled from the wrong side, an exemption list resolved against the
// profile's set instead of the control sets'. The subject here is the JSON that gets
// attached to the OU.
func TestNarrowingNeverWidensTheRenderedPolicy(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := drawRenderable(rt, "m")
		opts := drawNarrowOptions(rt, "p")

		narrowed, err := Narrow(m, opts)
		if err != nil {
			return
		}
		after, err := Pack(narrowed.Merged, packOpts())
		if err != nil {
			// The narrowed merge does not pack. Nothing is attached, so nothing
			// widened. This is a real case rather than a generator artifact: adding a
			// permitted set can oblige an exemption list the merge does not carry.
			return
		}
		before, err := Pack(m, packOpts())
		if err != nil {
			rt.Fatalf("the unnarrowed merge does not pack (%v); drawRenderable is supposed to produce "+
				"packable inputs, so this is a generator bug and it makes the property vacuous", err)
		}

		want := deniedSet(packedStatements(before))
		got := deniedSet(packedStatements(after))
		if missing := diffDenied(want, got); len(missing) > 0 {
			rt.Fatalf("the NARROWED policy widened permissions: the unnarrowed policy denied %d request(s) "+
				"the narrowed one permits.\nfirst missing: %s\nprofile regions=%v services=%v\n%s",
				len(missing), missing[0], opts.Regions, opts.Services, describe("merged", m))
		}
	})
}

// TestNarrowingIsIdempotent: narrowing by a set, then by the same set, changes
// nothing.
//
// Operationally this is what lets `vend` narrow and `verify` narrow again from the
// same profile and compare: if the second application moved the sets, drift would be
// reported on every healthy account.
func TestNarrowingIsIdempotent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := drawRenderable(rt, "m")
		opts := drawNarrowOptions(rt, "p")

		once, err := Narrow(m, opts)
		if err != nil {
			return
		}
		twice, err := Narrow(once.Merged, opts)
		if err != nil {
			rt.Fatalf("narrowing an already-narrowed merge by the same profile refused (%v); the second "+
				"application must be a no-op, or `verify` would refuse on an account `vend` built", err)
		}
		if got, want := mergedKey(twice.Merged), mergedKey(once.Merged); got != want {
			rt.Fatalf("narrowing twice differs from narrowing once:\n%s\n%s",
				describe("once", once.Merged), describe("twice", twice.Merged))
		}
	})
}

// TestNarrowingCommutesWithCombining.
//
// The order question an operator cannot see and cannot control: automat may merge two
// control sets and then apply the profile, or apply the profile to each and then
// merge. Both are intersections of the same three sets, so they must agree — and if
// they did not, the policy attached would depend on an implementation detail of the
// vend path rather than on the documents.
//
// Only the allowlists are compared. Narrow does not touch statements, and Combine
// renormalizes them, so a whole-key comparison would be asserting a property of
// mergeStatements that TestUnionIsAssociative already owns.
func TestNarrowingCommutesWithCombining(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		a := drawRenderable(rt, "a")
		b := drawRenderable(rt, "b")
		opts := drawNarrowOptions(rt, "p")

		// Narrow the union.
		ab := combine(rt, a, b)
		lhs, lerr := Narrow(ab, opts)
		// Narrow each side, then unite.
		na, aerr := Narrow(a, opts)
		nb, berr := Narrow(b, opts)

		if lerr != nil || aerr != nil || berr != nil {
			// A disjoint intersection somewhere. The two orders can legitimately
			// disagree about WHETHER they refuse — narrowing one side may empty a set
			// the union had already emptied, or vice versa — and both refusals attach
			// nothing. What must not differ is the answer when both succeed.
			return
		}
		rhs := combine(rt, na.Merged, nb.Merged)

		for _, axis := range []struct {
			name string
			pick func(*Merged) *AllowSet
		}{
			{"region", func(m *Merged) *AllowSet { return m.RegionAllowlist }},
			{"service", func(m *Merged) *AllowSet { return m.ServiceAllowlist }},
		} {
			if l, r := allowKey(axis.pick(lhs.Merged)), allowKey(axis.pick(rhs)); l != r {
				rt.Fatalf("narrow(A ∪ B) and narrow(A) ∪ narrow(B) disagree on the %s allowlist: %s vs %s. "+
					"The policy attached would depend on where in the vend path the profile was applied",
					axis.name, l, r)
			}
		}
	})
}

// drawNarrowOptions generates a profile's permitted sets.
//
// Drawn from the same vocabularies drawMerged uses, for the same reason its own
// vocabulary is small: the bug being hunted is a set operation losing or gaining a
// member, and that needs the two sides to OVERLAP PARTIALLY. Disjoint draws only
// exercise the refusal, and identical draws only exercise the identity.
//
// nil is drawn deliberately — an absent permitted set is the common case, most
// profiles constrain regions and say nothing about services — and the empty set is
// not, because Narrow refuses it and its own test covers the message.
func drawNarrowOptions(t *rapid.T, label string) NarrowOptions {
	opts := NarrowOptions{ProfileID: "generated"}
	if rapid.Bool().Draw(t, label+".hasRegions") {
		opts.Regions = rapid.SliceOfNDistinct(rapid.SampledFrom(probeRegions), 1, 3,
			func(s string) string { return s }).Draw(t, label+".regions")
	}
	if rapid.Bool().Draw(t, label+".hasServices") {
		opts.Services = rapid.SliceOfNDistinct(
			rapid.SampledFrom([]string{"s3", "ec2", "lambda", "batch"}), 1, 3,
			func(s string) string { return s }).Draw(t, label+".services")
	}
	return opts
}

// TestTheNarrowingPropertiesAreNotMostlyRefusals.
//
// Same argument as TestTheRenderedMonotonicityPropertyIsNotMostlyRefusals: three of
// the four properties above return early when Narrow refuses, which is correct and is
// also the shape of a property that tests nothing. If most draws were disjoint they
// would report a pass having compared almost no allowlists.
//
// Both early returns of the rendered property are measured, not just the first. It
// skips when Narrow refuses AND when the narrowed merge does not pack. The second
// currently measures zero, because drawRenderable always supplies an exemption list
// containing the namespaces that would brick an account — so this is an upper bound
// rather than a floor, and its job is to notice if that stops being true. Unlike the
// refusal count it is NOT asserted non-zero: a narrowing that then fails to pack is a
// legitimate outcome (constraining an axis can oblige an exemption list the merge does
// not carry) but not one worth contriving a draw for, since Pack's own tests own it.
func TestTheNarrowingPropertiesAreNotMostlyRefusals(t *testing.T) {
	const runs = 200
	var narrowed, refused, constrained, unpackable int
	rapid.Check(t, func(rt *rapid.T) {
		if narrowed+refused >= runs {
			return
		}
		m := drawRenderable(rt, "m")
		opts := drawNarrowOptions(rt, "p")
		got, err := Narrow(m, opts)
		if err != nil {
			refused++
			return
		}
		narrowed++
		// Count the draws where the profile actually intersected a set the control
		// sets had constrained — the only draws where a widening is even possible.
		if (m.RegionAllowlist != nil && opts.Regions != nil) || (m.ServiceAllowlist != nil && opts.Services != nil) {
			constrained++
		}
		if _, perr := Pack(got.Merged, packOpts()); perr != nil {
			unpackable++
		}
	})
	t.Logf("%d narrowings succeeded, %d refused, %d intersected an already-constrained axis, "+
		"%d of the successes did not pack", narrowed, refused, constrained, unpackable)
	if narrowed*4 < narrowed+refused {
		t.Errorf("only %d of %d generated narrowings succeeded; the properties are mostly returning early. "+
			"Widen the drawn sets so intersections survive more often", narrowed, narrowed+refused)
	}
	if refused == 0 {
		t.Error("no generated narrowing was refused, so the disjoint-intersection path is unexercised by " +
			"the properties and their early returns are dead code")
	}
	if constrained*10 < narrowed {
		t.Errorf("only %d of %d successful narrowings intersected an axis the control sets had already "+
			"constrained; the widening the properties hunt for is only possible on those draws, so the "+
			"suite is mostly asserting that an unconstrained axis stays unconstrained", constrained, narrowed)
	}
	if unpackable*2 > narrowed {
		t.Errorf("%d of %d successful narrowings then failed to pack, so the rendered-policy property is "+
			"mostly returning early on its SECOND check and comparing far fewer documents than its run "+
			"count suggests", unpackable, narrowed)
	}
}
