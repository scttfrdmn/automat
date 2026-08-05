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
// The governing principle is evidence, not judgment: a control is class
// config-rule when AWS's published mapping associates Config rules with it, and
// procedural otherwise. ROADMAP Phase 0 requires unmapped controls be marked
// procedural with a provenance note rather than dropped, so all fifteen appear.
//
// Three of the six procedural controls are arguably enforceable in AWS but are
// not mapped upstream (see candidateForEnforcement). Promoting one is a decision
// about what automat asserts on an operator's behalf, so it is left to human
// review rather than inferred here. gen/MAPPING-NOTES.md records the rationale
// for every one of the fifteen assignments.

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

// candidateForEnforcement flags procedural controls that could plausibly carry a
// technical enforcement class but are not mapped upstream.
//
// This is surfaced in MAPPING-NOTES.md rather than acted on. Promoting a control
// from procedural to config-rule changes what automat claims is enforced, and
// that claim ends up in an evidence manifest — so it is a human decision.
var candidateForEnforcement = map[string]string{
	"AC.L1-b.1.iv": "The conformance pack contains rules that bear directly on publicly accessible " +
		"content (s3-bucket-public-read-prohibited, s3-bucket-public-write-prohibited, and the " +
		"various *-not-public rules), but AWS maps them to AC.L1-3.1.1 and AC.L1-3.1.2 rather than " +
		"to 3.1.22. Reusing them here would mean asserting an enforcement AWS does not claim.",
	"SC.L1-b.1.xi": "Subnetwork separation is partially observable (subnet-auto-assign-public-ip-disabled, " +
		"ec2-instance-no-public-ip), but AWS maps those to other controls. Whether a topology " +
		"genuinely separates public components is an architecture question a rule cannot answer.",
	"SI.L1-b.1.xiv": "guardduty-enabled-centralized is mapped to SI.L1-3.14.1 and 3.14.2 upstream; " +
		"a managed service arguably satisfies 'update mechanisms when new releases are available' " +
		"implicitly, but no rule observes the update itself.",
}

// checkCandidateNotes keeps candidateForEnforcement honest about the artifact.
//
// A note explaining why a control was left procedural is misleading if that
// control is no longer procedural, and it is the kind of stale comment nobody
// notices. Compiling fails rather than shipping a wrong rationale.
func checkCandidateNotes(controls artifact.Controls) error {
	byID := make(map[string]artifact.Control, len(controls))
	for _, c := range controls {
		byID[c.ID] = c
	}
	ids := make([]string, 0, len(candidateForEnforcement))
	for id := range candidateForEnforcement {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			return fmt.Errorf("candidateForEnforcement names control %s, which the catalog does not contain "+
				"(gen/catalog/enforcement.go)", id)
		}
		if !c.Enforces(artifact.EnforcementProcedural) {
			return fmt.Errorf("candidateForEnforcement explains why %s was left procedural, but the compiled "+
				"control is not procedural; remove the note and update gen/MAPPING-NOTES.md", id)
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
	// Set-valued parameters. These are conceptually unions of blocked items or
	// intersections of allowed ones, but the pack encodes them as
	// comma-separated strings, and merging strings by guesswork is exactly what
	// DESIGN §9 forbids. Left exact until the union code can model them
	// properly; recorded in docs/open-questions.md.
	"blockedActionsPatterns": artifact.OrderExact,
	"authorizedTcpPorts":     artifact.OrderExact,
	"blockedPort1":           artifact.OrderExact,
	"blockedPort2":           artifact.OrderExact,
	"blockedPort3":           artifact.OrderExact,
	"blockedPort4":           artifact.OrderExact,
	"blockedPort5":           artifact.OrderExact,
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
