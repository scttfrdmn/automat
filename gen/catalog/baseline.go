// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// The baseline-protection meta-control (DESIGN §10): the control set that guards
// the guards, attached at the OU with every vend.
//
// Compiled from a curated source file rather than written as Go literals, because
// DESIGN §10 says so in as many words — "represent as `enforcement:
// baseline-protection` entries in the artifact, not hardcoded, so L2-minded users
// can extend the deny list". A deny list encoded in Go cannot be extended by an
// institution without a fork, and the whole point of the class is that a campus
// adds its own protections to it.
//
// What IS in Go is the checklist: designSection10Actions is a transcription of
// §10's five bullets, and the compile refuses to build a source file whose actions
// stray from it without saying why. That inverts the usual drift risk. The data can
// grow — that is its purpose — but it cannot quietly *shrink* below the design, and
// an addition has to justify itself in the artifact where a reviewer will read it.
const (
	baselineSourceFile = "baseline-protection.json"
	baselineID         = "baseline-protection"
	baselineTitle      = "automat baseline protection"
)

const baselineDescription = "The controls that protect automat's own baseline in a vended account: " +
	"the configuration recorder, the delivery channel, the conformance pack, the trail, the account's " +
	"membership in its organization, the two baseline roles, and the root user. Attached at the OU with " +
	"every vend (DESIGN §10). Extend it rather than replacing it: every entry is data."

// baselineDoc is the curated baseline-protection source.
type baselineDoc struct {
	Comment    string                      `json:"_comment"`
	Source     baselineSource              `json:"source"`
	Exemptions map[string]baselineExempt   `json:"exemptions"`
	Controls   []baselineControlSourceItem `json:"controls"`
}

// baselineSource is the provenance block. Deliberately NOT the shared `upstream`
// type: there is no upstream document, and reusing a struct with an
// `upstream_sha256` field would invite filling it with something.
type baselineSource struct {
	ControlSet    string `json:"control_set"`
	Version       string `json:"version"`
	URI           string `json:"uri"`
	DesignSection string `json:"design_section"`
	AuthoredAt    string `json:"authored_at"`
	Note          string `json:"note"`
}

// baselineExempt is a named, reusable exemption.
//
// Named and shared rather than repeated per control on purpose: the merge groups
// exemption buckets by principals AND reason text, so four controls exempting the
// same role with four differently-worded reasons occupy four statements instead of
// one. A shared name is how the source file says "this is the same hole", and the
// packed policy shows it as one statement with four origins.
type baselineExempt struct {
	Reason     string   `json:"reason"`
	Principals []string `json:"principals"`
}

// baselineControlSourceItem is one protection control.
type baselineControlSourceItem struct {
	ID        string             `json:"id"`
	Title     string             `json:"title"`
	Statement string             `json:"statement"`
	Sid       string             `json:"sid"`
	Actions   []string           `json:"actions"`
	Resources []string           `json:"resources"`
	Exemption string             `json:"exemption,omitempty"`
	Condition artifact.Condition `json:"condition,omitempty"`

	// DesignBasis names the DESIGN §10 bullet the control implements. Required:
	// a protection control with no stated basis is a Deny nobody can trace to a
	// decision, and this artifact's whole authority is that §10 asked for it.
	DesignBasis string `json:"design_basis"`
	// ExtendsDesign is required for any action §10 does not enumerate. See
	// checkAgainstDesign.
	ExtendsDesign string `json:"extends_design,omitempty"`
}

// reBaselineTimestamp matches the second-precision UTC form every timestamp in a
// compiled artifact takes. Spelled out here rather than imported from
// internal/artifact, which keeps it unexported: a loosened validator there must
// not quietly loosen what the compiler accepts.
var reBaselineTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// designSection10Actions is DESIGN §10's deny list, transcribed.
//
// Kept as patterns in the same form §10 writes them, so the two can be read side
// by side — TestTheChecklistCoversEveryDesignBullet does exactly that against
// DESIGN.md, which is what keeps this from becoming a stale copy of a document
// that moved.
//
// §10's fifth bullet — the root-user deny — is deliberately NOT here. Its action
// is `*`, and the first version of this list included it: every action matched
// the wildcard, so every action was "enumerated by the design" and the whole
// check silently passed on anything. A checklist with an entry that matches
// everything is not a checklist. Bullet 5 is handled by rootDenyIsWellFormed
// instead, which is about the condition rather than the action — which is what
// that bullet is actually about.
var designSection10Actions = []string{
	// Bullet 1: config recorder, delivery channel, conformance pack.
	"config:DeleteConfigurationRecorder",
	"config:StopConfigurationRecorder",
	"config:DeleteDeliveryChannel",
	"config:DeleteConformancePack",
	"config:PutConformancePack",
	// Bullet 2: the trail.
	"cloudtrail:StopLogging",
	"cloudtrail:DeleteTrail",
	"cloudtrail:UpdateTrail",
	// Bullet 3.
	"organizations:LeaveOrganization",
	// Bullet 4: IAM mutation of the baseline roles.
	"iam:Update*",
	"iam:Delete*",
	"iam:Put*",
	"iam:Attach*",
	"iam:Detach*",
}

// principalArnKey is the condition key a whole-account Deny must constrain.
const principalArnKey = "aws:PrincipalArn"

// artifactStatement is the control text as it appears in the compiled artifact:
// the requirement, its design basis, and — where the control departs from DESIGN
// §10 — the reason.
//
// Concatenated into `statement` rather than carried in fields of their own, because
// adding fields to the control artifact schema for this would be a schema change
// (rule 6) to record a fact that is prose either way. The important half is that
// the reason travels: checkAgainstDesign refuses a departure with no explanation on
// the grounds that the reviewer approving the account's preventive posture will read
// it, and the artifact is the only document that reviewer is guaranteed to have.
// The source file is upstream of a compile; it is not what gets shipped.
func (c baselineControlSourceItem) artifactStatement() string {
	out := c.Statement + " [Design basis: " + c.DesignBasis + "]"
	if c.ExtendsDesign != "" {
		out += " [Departs from the design as written: " + c.ExtendsDesign + "]"
	}
	return out
}

// compileBaseline loads and compiles the baseline-protection control set.
func compileBaseline(srcDir string) (*artifact.Artifact, error) {
	var doc baselineDoc
	fileHash, err := readJSONAndHash(filepath.Join(srcDir, baselineSourceFile), &doc)
	if err != nil {
		return nil, err
	}
	if err := doc.check(); err != nil {
		return nil, err
	}

	controls := make(artifact.Controls, 0, len(doc.Controls))
	for _, c := range doc.Controls {
		st := artifact.SCPStatement{
			Sid:       c.Sid,
			Effect:    "Deny",
			Action:    c.Actions,
			Resource:  c.Resources,
			Condition: c.Condition,
		}
		if c.Exemption != "" {
			ex, ok := doc.Exemptions[c.Exemption]
			if !ok {
				return nil, fmt.Errorf("%s: control %s names exemption %q, which the file does not define; "+
					"a dangling exemption name would compile to a Deny with NO hole where the author intended "+
					"one, or with a hole they did not write, depending on the typo",
					baselineSourceFile, c.ID, c.Exemption)
			}
			for _, p := range ex.Principals {
				st.ExemptPrincipals = append(st.ExemptPrincipals, artifact.ExemptPrincipal{
					Principal: p,
					Reason:    ex.Reason,
				})
			}
		}
		controls = append(controls, artifact.Control{
			ID:          c.ID,
			Title:       c.Title,
			Statement:   c.artifactStatement(),
			Enforcement: []artifact.EnforcementClass{artifact.EnforcementBaselineProtection},
			SCP:         &artifact.SCP{Statements: []artifact.SCPStatement{st}},
		})
	}

	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{
			ID:          baselineID,
			Title:       baselineTitle,
			Description: baselineDescription,
			Sources:     baselineProvenance(doc.Source, fileHash),
			CompiledAt:  doc.Source.AuthoredAt,
		},
		Controls: controls,
	}
	if err := a.SetContentHash(); err != nil {
		return nil, fmt.Errorf("hash artifact %s: %w", baselineID, err)
	}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("compiled artifact %s does not satisfy its own schema: %w", baselineID, err)
	}
	return a, nil
}

// baselineProvenance records where this control set came from.
//
// One source entry, and its hash is of the curated file — which is the whole
// chain, because there IS no upstream publication. That absence is stated in the
// note rather than left to inference: a reader who finds a single self-referential
// source on every other catalog would be right to treat it as a broken chain, and
// they should be able to tell this apart from that at a glance.
func baselineProvenance(s baselineSource, fileHash string) artifact.Sources {
	return artifact.Sources{{
		Catalog:     s.ControlSet,
		Version:     s.Version,
		URI:         s.URI,
		RetrievedAt: s.AuthoredAt,
		SHA256:      fileHash,
		Note: fmt.Sprintf("automat's own control set, specified by %s. There is no upstream publication to "+
			"hash: the sha256 is of the curated source file %s, and %s is version-controlled in this "+
			"repository. Every control names the bullet it implements, and any action the design does not "+
			"enumerate must say why it is present.", s.DesignSection, baselineSourceFile, s.DesignSection),
	}}
}

// check validates the source file before anything is compiled from it.
func (d *baselineDoc) check() error {
	if err := d.checkProvenance(); err != nil {
		return err
	}
	if len(d.Controls) == 0 {
		return fmt.Errorf("%s defines no controls; an empty baseline-protection set is a vend that attaches "+
			"nothing while reporting that it attached the baseline", baselineSourceFile)
	}

	for name, ex := range d.Exemptions {
		if ex.Reason == "" {
			return fmt.Errorf("%s: exemption %q has no reason; an unexplained hole in a protection control is "+
				"indistinguishable from an escape hatch, and it is what a reviewer of this file is reading for",
				baselineSourceFile, name)
		}
		if len(ex.Principals) == 0 {
			return fmt.Errorf("%s: exemption %q names no principals", baselineSourceFile, name)
		}
	}

	seenID := map[string]bool{}
	seenSid := map[string]bool{}
	used := map[string]bool{}
	for _, c := range d.Controls {
		switch {
		case c.ID == "":
			return fmt.Errorf("%s: a control has no id", baselineSourceFile)
		case seenID[c.ID]:
			return fmt.Errorf("%s: duplicate control id %s", baselineSourceFile, c.ID)
		}
		seenID[c.ID] = true

		if c.Sid == "" {
			return fmt.Errorf("%s: control %s has no sid", baselineSourceFile, c.ID)
		}
		if seenSid[c.Sid] {
			// Not merely untidy: two statements sharing a Sid in one rendered policy
			// is a MalformedPolicyDocument at CreatePolicy, mid-vend, with the
			// account already created. The packer derives merged Sids for that
			// reason; a hand-authored collision should die at compile time.
			return fmt.Errorf("%s: control %s reuses sid %s; IAM requires a Sid to be unique within a "+
				"policy document and rejects the whole policy otherwise", baselineSourceFile, c.ID, c.Sid)
		}
		seenSid[c.Sid] = true

		if c.Title == "" || c.Statement == "" {
			return fmt.Errorf("%s: control %s needs both a title and a statement; the statement is what a "+
				"reviewer reads to decide whether the Deny is the right one", baselineSourceFile, c.ID)
		}
		if len(c.Actions) == 0 {
			return fmt.Errorf("%s: control %s names no actions, so it denies nothing", baselineSourceFile, c.ID)
		}
		if len(c.Resources) == 0 {
			return fmt.Errorf("%s: control %s names no resources; an SCP statement must scope to at least "+
				"\"*\", and omitting it silently would let the packer choose", baselineSourceFile, c.ID)
		}
		if c.Exemption != "" {
			if _, ok := d.Exemptions[c.Exemption]; !ok {
				return fmt.Errorf("%s: control %s names undefined exemption %q", baselineSourceFile, c.ID, c.Exemption)
			}
			used[c.Exemption] = true
		}
		if err := d.checkAgainstDesign(c); err != nil {
			return err
		}
	}

	// An exemption nobody uses is a hole waiting to be attached to a control by
	// someone who trusts that it was reviewed for the control they are writing.
	var unused []string
	for name := range d.Exemptions {
		if !used[name] {
			unused = append(unused, name)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		return fmt.Errorf("%s defines exemption(s) %v that no control uses; delete them rather than leaving "+
			"a reviewed-looking hole for a future control to pick up", baselineSourceFile, unused)
	}
	return nil
}

// checkAgainstDesign holds the source file to DESIGN §10.
//
// Every control must cite the bullet it implements, and any action §10 does not
// enumerate must be justified in the artifact itself. Not a style rule: the deny
// list is meant to be extended, so "an action appeared here" cannot be treated as
// suspicious by itself — what can be required is that the reason travels with it,
// into the compiled artifact, where the reviewer who has to sign off on the
// account's preventive posture will actually see it.
func (d *baselineDoc) checkAgainstDesign(c baselineControlSourceItem) error {
	if c.DesignBasis == "" {
		return fmt.Errorf("%s: control %s has no design_basis; every protection control must name the "+
			"DESIGN §10 bullet it implements, or state that it extends the list", baselineSourceFile, c.ID)
	}

	principalScoped, err := rootDenyIsWellFormed(c)
	if err != nil {
		return err
	}

	var extra []string
	for _, a := range c.Actions {
		switch {
		case a == "*" && principalScoped:
			// DESIGN §10's fifth bullet: a Deny on every action, narrowed to a
			// principal by condition. Covered by the design, and rootDenyIsWellFormed
			// has already established that the narrowing is present.
		case coveredByDesign(a):
		default:
			extra = append(extra, a)
		}
	}
	if len(extra) > 0 && c.ExtendsDesign == "" {
		sort.Strings(extra)
		return fmt.Errorf("%s: control %s denies %v, which DESIGN §10 does not enumerate, and carries no "+
			"extends_design explaining why. The deny list is meant to grow, so this is not a refusal to "+
			"extend it — it is a requirement that the reason travel into the artifact, where the reviewer "+
			"approving the account's preventive posture will read it", baselineSourceFile, c.ID, extra)
	}
	// There is deliberately no converse check — no "extends_design present but
	// nothing extends the design, so delete it".
	//
	// The first version had one, and it was wrong in a way worth recording,
	// because it read as a tidiness rule while actually asserting something false:
	// that an extra action is the ONLY way a control can depart from §10. Three of
	// the shipped controls depart in other ways. BP.ORG-1 denies exactly the action
	// §10 names and departs by carrying no exemption where every neighbouring
	// control has one. BP.IAM-1 and BP.ROOT-1 wildcard the ARN partition so the
	// control also holds in GovCloud, which §10's literal `arn:aws:` does not. Each
	// of those is a decision a reviewer needs, and the check would have demanded
	// its deletion. Requiring a true statement to be removed is worse than
	// tolerating a stale one: the stale caveat is visible to the reviewer, and the
	// deleted one is not.
	return nil
}

// rootDenyIsWellFormed checks the one control shape that can brick an account,
// and reports whether the control narrows itself by principal.
//
// DESIGN §10's fifth bullet is a Deny on `*` narrowed by aws:PrincipalArn to the
// root user. That shape is correct and necessary; it is also one missing condition
// away from denying every action to every principal in the account, with no path
// back that does not go through detaching the policy. Nothing else in the source
// file needs a wildcard action, so the rule is: an action list containing `*` must
// carry a condition on aws:PrincipalArn, and must carry no exemption — an
// exemption on a deny-everything statement is an all-powerful principal, which is
// the opposite of what the bullet is for.
//
// The narrowing is required to be a condition rather than merely "some condition",
// because the failure mode is specific: a condition on any other key still leaves
// the statement denying every action to every principal whenever that key matches.
func rootDenyIsWellFormed(c baselineControlSourceItem) (principalScoped bool, err error) {
	wildcard := false
	for _, a := range c.Actions {
		if a == "*" {
			wildcard = true
		}
	}
	for _, keys := range c.Condition {
		if _, ok := keys[principalArnKey]; ok {
			principalScoped = true
		}
	}
	if !wildcard {
		return principalScoped, nil
	}

	if !principalScoped {
		return false, fmt.Errorf("%s: control %s denies action \"*\" without a condition on %s. "+
			"An unconditional Deny on every action in an SCP denies every call every principal in the "+
			"account can make, including the ones needed to remove the policy; DESIGN §10's only wildcard "+
			"Deny is the root-user one, which is narrowed by principal", baselineSourceFile, c.ID, principalArnKey)
	}
	if c.Exemption != "" {
		return false, fmt.Errorf("%s: control %s denies action \"*\" and names exemption %q. An exemption on a "+
			"deny-everything statement is a principal no control in this account applies to, which is a "+
			"larger hole than the one the control closes", baselineSourceFile, c.ID, c.Exemption)
	}
	return true, nil
}

// coveredByDesign reports whether an action is one DESIGN §10 enumerates.
//
// Glob-matched because §10 writes bullet 4 as patterns (iam:Update* and friends).
// path.Match's `*` does not cross `/`, and no IAM action contains one.
func coveredByDesign(action string) bool {
	for _, pattern := range designSection10Actions {
		if ok, err := path.Match(pattern, action); err == nil && ok {
			return true
		}
	}
	return false
}

// checkProvenance refuses to compile a source whose own provenance block is
// incomplete, for the reason the cmmc-l1 loader's version of this gives: a
// half-filled provenance block reads as verified to a reviewer.
func (d *baselineDoc) checkProvenance() error {
	s := d.Source
	switch {
	case s.ControlSet == "":
		return fmt.Errorf("%s: provenance block names no control_set", baselineSourceFile)
	case s.DesignSection == "":
		return fmt.Errorf("%s: provenance block names no design_section; this control set's authority is a "+
			"section of the design document, so the artifact must say which", baselineSourceFile)
	case s.URI == "":
		return fmt.Errorf("%s: provenance block has no uri", baselineSourceFile)
	case s.Note == "":
		return fmt.Errorf("%s: provenance block has no note. This is the one catalog with no upstream "+
			"publication to hash, and the note is where that is stated; without it the single "+
			"self-referential source reads as a broken provenance chain", baselineSourceFile)
	case s.AuthoredAt == "":
		return fmt.Errorf("%s: provenance block has no authored_at; compiled_at is derived from it so that "+
			"`make catalogs` is reproducible", baselineSourceFile)
	case !reBaselineTimestamp.MatchString(s.AuthoredAt):
		return fmt.Errorf("%s: authored_at %q is not second-precision UTC RFC 3339 (2026-08-05T00:00:00Z)",
			baselineSourceFile, s.AuthoredAt)
	}
	return nil
}
