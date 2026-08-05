// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Enforcement assignment for CMMC 2.0 Level 1.
//
// There are two layers, kept structurally distinct because they carry different
// authority:
//
//   - The **aws-mapping layer**: a control is class config-rule when AWS's
//     published conformance-pack mapping associates Config rules with it. This
//     layer is mechanically generated from the mapping and is never hand-edited;
//     the mapping's sha256 in artifact.sources is what vouches for it.
//   - The **curated layer** (curatedBindings, below): bindings this project
//     asserts itself, each carrying a rationale into the artifact. Reviewed by
//     hand, one at a time.
//
// ROADMAP Phase 0 requires unmapped controls be marked procedural with a
// provenance note rather than dropped, so all fifteen requirements appear.
// A curated binding does not remove a control's procedural class: the rationales
// below explain what the rules do and do not observe, and dropping the
// attestation would claim more coverage than the rules deliver (DESIGN §12).
// gen/MAPPING-NOTES.md records the rationale for every one of the fifteen
// assignments.

// attestation describes the stub written for a procedural control.
type attestationSpec struct {
	template  string
	frequency string
	guidance  string
}

// proceduralSpecs gives each procedural control its attestation stub.
//
// Frequency is annual throughout: CMMC Level 1 requires an annual
// self-assessment and affirmation (32 CFR 170.15(c)), so an annual cadence is
// what the assessment cycle actually calls for.
var proceduralSpecs = map[string]attestationSpec{
	"AC.L1-b.1.iv": {
		template:  "publicly-accessible-content.md",
		frequency: "annual",
		guidance: "Record who reviews content before it is posted to publicly accessible systems, " +
			"and how that review is evidenced. Note that automat's detective baseline does monitor " +
			"public exposure of several AWS resource types under other controls; this attestation " +
			"covers the review process itself, which no Config rule can observe.",
	},
	"MP.L1-b.1.vii": {
		template:  "media-sanitization.md",
		frequency: "annual",
		guidance: "Record the sanitization or destruction procedure for media containing Federal " +
			"Contract Information before disposal or reuse, including who performs it and how it is " +
			"evidenced. AWS manages sanitization of its own storage media; this attestation covers " +
			"media in your custody.",
	},
	"PE.L1-b.1.viii": {
		template:  "physical-access.md",
		frequency: "annual",
		guidance: "Record how physical access to systems, equipment, and operating environments is " +
			"limited to authorized individuals. For workloads wholly in AWS, this is largely " +
			"inherited from AWS's data-center controls; name the AWS compliance report you rely on " +
			"and describe controls for any on-premises equipment in scope.",
	},
	"PE.L1-b.1.ix": {
		template:  "visitor-access.md",
		frequency: "annual",
		guidance: "Record visitor escort and monitoring, physical access audit logs, and management " +
			"of physical access devices. This requirement was split into three 800-171 R2 " +
			"requirements (3.10.3, 3.10.4, 3.10.5); address all three. For AWS-hosted workloads " +
			"this is largely inherited; name the AWS compliance report you rely on.",
	},
	"SC.L1-b.1.xi": {
		template:  "publicly-accessible-subnetworks.md",
		frequency: "annual",
		guidance: "Record the network architecture that separates publicly accessible system " +
			"components from internal networks — in AWS terms, the VPC subnet layout, route tables, " +
			"and security group boundaries. automat cannot verify an architecture is correctly " +
			"segmented, only that specific resources are not publicly exposed.",
	},
	"SI.L1-b.1.xiv": {
		template:  "malicious-code-updates.md",
		frequency: "annual",
		guidance: "Record how malicious-code protection mechanisms are updated when new releases " +
			"become available, including the update mechanism and its cadence.",
	},
}

// curatedBindings are Config rule bindings this project asserts itself, for
// controls AWS's mapping leaves without technical coverage.
//
// Each is reviewed by hand and each carries its rationale into the artifact, so
// a reader of catalogs/cmmc-l1.json can audit automat's judgment separately from
// AWS's. These bindings are additive: the control keeps its procedural class and
// its attestation stub, because in all three cases the rules observe a *symptom*
// of the requirement and not the requirement itself, and DESIGN §12 requires the
// tool state that limit rather than paper over it.
//
// The rules named here are all already in the conformance pack — nothing is
// invented, only bound to a second control. AWS maps them to other requirements;
// what is curated is the additional association, not the rule.
var curatedBindings = map[string][]curatedBinding{
	"AC.L1-b.1.iv": {{
		rule: "s3-bucket-public-read-prohibited",
		rationale: "Control public information: this rule detects the most common way Federal " +
			"Contract Information becomes publicly readable. AWS's mapping binds it to AC.L1-3.1.1 " +
			"and 3.1.2 rather than to 3.1.22, so the association with the public-information " +
			"requirement is automat's own. It observes exposure, not the review process the " +
			"requirement mandates, which is why the attestation stub remains.",
	}, {
		rule: "s3-bucket-public-write-prohibited",
		rationale: "Control public information: a publicly writable bucket means content can be " +
			"posted to a publicly accessible system with no review at all. Bound here by automat " +
			"rather than by AWS, which maps it to the general access-control requirements.",
	}, {
		rule: "s3-account-level-public-access-blocks-periodic",
		rationale: "Control public information: account-level public access blocks are the " +
			"preventive floor under the two bucket-level rules above, so the three are bound " +
			"together. Detects the case where a reviewer's intent is correct but the account " +
			"permits public exposure anyway.",
	}},
	"SC.L1-b.1.xi": {{
		rule: "subnet-auto-assign-public-ip-disabled",
		rationale: "Public-access system separation: a subnet that auto-assigns public IPs is not " +
			"an internal network, so this rule detects the clearest violation of the separation " +
			"the requirement demands. AWS maps it elsewhere. Whether a topology genuinely " +
			"separates publicly accessible components from internal ones is an architecture " +
			"question no rule can answer, which is why the attestation stub remains.",
	}, {
		rule: "ec2-instance-no-public-ip",
		rationale: "Public-access system separation: an instance with a public IP sits on the " +
			"boundary regardless of subnet intent. Bound here by automat as the instance-level " +
			"counterpart to the subnet rule above; AWS maps it to boundary protection instead.",
	}},
	"SI.L1-b.1.xiv": {{
		rule: "guardduty-enabled-centralized",
		rationale: "Update malicious code protection: a managed detection service updates its own " +
			"threat intelligence, so keeping it enabled is the AWS-native form of 'update " +
			"protection mechanisms when new releases are available'. AWS maps this rule to " +
			"SI.L1-3.14.1 and 3.14.2, not to 3.14.5, so the association is automat's. No rule " +
			"observes the update itself, and it says nothing about protection mechanisms on " +
			"instances, which is why the attestation stub remains.",
	}},
}

// curatedBinding is one hand-reviewed rule binding and the reason for it.
type curatedBinding struct {
	rule      string // conformance-pack rule name, which must exist in the pack
	rationale string
}

// checkCuratedBindings keeps the curated layer honest about the artifact.
//
// A rationale describing a control automat does not compile, or a curated
// binding that did not survive into the artifact, is the kind of stale claim
// nobody notices — and these claims end up in an evidence manifest. Compiling
// fails rather than shipping one.
func checkCuratedBindings(controls artifact.Controls) error {
	byID := make(map[string]artifact.Control, len(controls))
	for _, c := range controls {
		byID[c.ID] = c
	}
	ids := make([]string, 0, len(curatedBindings))
	for id := range curatedBindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			return fmt.Errorf("curatedBindings names control %s, which the catalog does not contain "+
				"(gen/catalog/enforcement.go)", id)
		}
		for _, b := range curatedBindings[id] {
			found := false
			for _, r := range c.ConfigRules {
				if r.Name != b.rule {
					continue
				}
				found = true
				if r.Provenance != artifact.ProvenanceCurated {
					return fmt.Errorf("control %s binds rule %s with provenance %q, but it is a curated "+
						"binding; the aws-mapping layer must never absorb a curated one", id, b.rule, r.Provenance)
				}
				if r.Rationale != b.rationale {
					return fmt.Errorf("control %s binds rule %s with a rationale that is not the reviewed "+
						"one from curatedBindings (gen/catalog/enforcement.go)", id, b.rule)
				}
			}
			if !found {
				return fmt.Errorf("curatedBindings binds rule %s to control %s, but the compiled control "+
					"does not carry it", b.rule, id)
			}
		}
	}
	return nil
}

// paramOrders assigns each conformance-pack parameter its union order.
//
// The order encodes which direction is stricter, so union can resolve two
// control sets that bind the same parameter (DESIGN §9). Where no ordering is
// meaningful — booleans, port lists, action patterns — the order is exact, which
// makes a conflict a hard error demanding explicit resolution rather than a
// silent guess.
var paramOrders = map[string]artifact.ParamOrder{
	// Age and lifetime bounds: a shorter maximum is stricter.
	"maxAccessKeyAge":       artifact.OrderMin,
	"MaxPasswordAge":        artifact.OrderMin,
	"maxCredentialUsageAge": artifact.OrderMin,
	// Strength minimums: a larger requirement is stricter.
	"MinimumPasswordLength":   artifact.OrderMax,
	"PasswordReusePrevention": artifact.OrderMax,
	// Booleans: no ordering. Two sets disagreeing must be resolved explicitly.
	"RequireLowercaseCharacters":     artifact.OrderExact,
	"RequireUppercaseCharacters":     artifact.OrderExact,
	"RequireNumbers":                 artifact.OrderExact,
	"RequireSymbols":                 artifact.OrderExact,
	"alarmActionRequired":            artifact.OrderExact,
	"insufficientDataActionRequired": artifact.OrderExact,
	"okActionRequired":               artifact.OrderExact,
	// Deny-shaped sets: the value enumerates prohibited items, so prohibiting
	// more is stricter and union is the monotone resolution.
	"blockedActionsPatterns": artifact.OrderSetUnion,
	// The five blockedPort parameters each hold one port in the pack, but they
	// are one prohibited-port set spread across five slots, and set-union is the
	// only monotone order for a member of such a set: dropping either input's
	// port would permit traffic that input forbade. See the caveat in
	// gen/MAPPING-NOTES.md — RESTRICTED_INCOMING_TRAFFIC types each parameter as
	// a single integer, so Phase 4's union must re-slot the unioned ports across
	// blockedPort1..5 (and hard-error above five) rather than emit a joined
	// value the rule would reject.
	"blockedPort1": artifact.OrderSetUnion,
	"blockedPort2": artifact.OrderSetUnion,
	"blockedPort3": artifact.OrderSetUnion,
	"blockedPort4": artifact.OrderSetUnion,
	"blockedPort5": artifact.OrderSetUnion,
	// Allow-shaped sets: the value enumerates permitted items, so permitting
	// fewer is stricter and intersection is the monotone resolution.
	"authorizedTcpPorts": artifact.OrderSetIntersect,
}

// orderFor returns the declared union order for a parameter.
//
// An unknown parameter is an error, not a defaulted guess: a new pack parameter
// silently defaulting to exact could turn a legitimate union into a hard
// conflict, and defaulting to min or max could silently loosen a control.
func orderFor(rule, param string) (artifact.ParamOrder, error) {
	if o, ok := paramOrders[param]; ok {
		return o, nil
	}
	known := make([]string, 0, len(paramOrders))
	for k := range paramOrders {
		known = append(known, k)
	}
	sort.Strings(known)
	return "", fmt.Errorf("rule %s has parameter %q with no declared union order — "+
		"add it to paramOrders in gen/catalog/enforcement.go with a rationale in gen/MAPPING-NOTES.md; "+
		"union must never guess which direction is stricter (DESIGN §9). Known parameters: %v",
		rule, param, known)
}
