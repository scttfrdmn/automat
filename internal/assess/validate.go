// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"fmt"
	"regexp"
	"strings"
)

// Problem is one thing wrong with a profile: where, what, and what would fix
// it. Mirrors internal/artifact's own shape exactly (CLAUDE.md rule 7:
// errors are values with remediation text). Not shared by import, because
// internal/artifact validates a different document and a shared type would
// let this package's problems masquerade as an artifact's — the same
// reasoning internal/evidence and internal/envprofile each keep their own
// copy of safe() for.
type Problem struct {
	Path    string
	Message string
	Fix     string
}

func (p Problem) Error() string {
	if p.Fix == "" {
		return fmt.Sprintf("%s: %s", p.Path, p.Message)
	}
	return fmt.Sprintf("%s: %s — %s", p.Path, p.Message, p.Fix)
}

// ValidationError lists every problem Validate found in one pass.
type ValidationError struct {
	Subject  string
	Problems []Problem
}

func (v *ValidationError) Error() string {
	var sb strings.Builder
	subject := v.Subject
	if subject == "" {
		subject = "document"
	}
	fmt.Fprintf(&sb, "%s is invalid (%d problem", subject, len(v.Problems))
	if len(v.Problems) != 1 {
		sb.WriteByte('s')
	}
	sb.WriteString("):")
	for _, p := range v.Problems {
		fmt.Fprintf(&sb, "\n  - %s", p.Error())
	}
	return sb.String()
}

func (v *ValidationError) Unwrap() []error {
	out := make([]error, len(v.Problems))
	for i, p := range v.Problems {
		out[i] = p
	}
	return out
}

type problems struct {
	list []Problem
}

func (p *problems) add(path, message, fix string) {
	p.list = append(p.list, Problem{Path: path, Message: message, Fix: fix})
}

// safe renders an untrusted string for inclusion in an error message —
// AUDIT-0 M1's discipline, restated here because an obligation profile is
// attacker-controlled input in the threat model exactly as a control
// artifact is.
func safe(s string) string {
	const max = 120
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}

// Regexes mirror schema/obligation-profile-v1.schema.json's $defs. The
// schema conformance test in internal/artifact is what keeps the published
// contract itself honest; TestValidateAgreesWithTheSchema in this package
// keeps this copy in step with that contract.
var (
	reSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reSlug   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	reDate   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// prose forbids control characters (a value rendered into a report or
	// table, where a newline forges a row); long_prose additionally permits
	// newlines and tabs.
	reProse     = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
	reLongProse = regexp.MustCompile(`^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$`)
	// reRoundTripID mirrors schema/operator-determinations-v1.schema.json's
	// $defs/round_trip_id: a determination's id is typed by an operator and
	// later retyped or searched for (CLAUDE.md rule 8), so no whitespace or
	// shell metacharacter may enter it.
	reRoundTripID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

const maxRoundTripID = 128

func validRoundTripID(s string) bool {
	return s != "" && len(s) <= maxRoundTripID && reRoundTripID.MatchString(s)
}

const (
	maxProse     = 512
	maxLongProse = 8192
)

func validProse(s string) bool {
	return s != "" && len(s) <= maxProse && reProse.MatchString(s)
}

func validLongProse(s string) bool {
	return s != "" && len(s) <= maxLongProse && reLongProse.MatchString(s)
}

// The closed vocabularies the schema enumerates.
var (
	allStatuses          = []string{"in-force", "proposed", "superseded", "phased"}
	allCitationRoles     = []string{"creates", "operationalizes", "supersedes", "related"}
	allRevisionPolicies  = []string{"pinned", RevisionOperatorDetermined}
	allAssessmentTypes   = []string{"self", "third-party", "attestation-only"}
	allAuditedByIssuer   = []string{"yes", "no", "not-stated"}
	allDocumentationSubs = []string{"routinely", "on-request", "not-submitted"}
	allScoringMethods    = []string{"none", "dfars-110-weighted"}
	allAttestationRoles  = []string{"authored-by", "adopted-by", "reviewed-by", "interpreted-by", "format-validated-by"}
	allSignatureFormats  = []string{"detached-ed25519", "oidc-identity-bundle"}
)

func oneOf(s string, allowed []string) bool {
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}

func joined(allowed []string) string {
	return strings.Join(allowed, ", ")
}

// Validate checks the profile against schema/obligation-profile-v1.schema.json's
// constraints and returns a *ValidationError listing every problem found.
//
// Reports every problem in one pass rather than stopping at the first — the
// same reasoning artifact.Validate gives: an operator fixing a hand-edited
// profile wants the whole list.
func (p *Profile) Validate() error {
	var probs problems

	if p.SchemaVersion == "" {
		probs.add("schema_version", "missing", "set it, e.g. \"1.0.0\"")
	} else if !reSemver.MatchString(p.SchemaVersion) {
		probs.add("schema_version", fmt.Sprintf("%s is not semver", safe(p.SchemaVersion)), "use MAJOR.MINOR.PATCH")
	}

	p.validateMeta(&probs)
	if !oneOf(p.Status, allStatuses) {
		probs.add("status", fmt.Sprintf("%s is not one of %s", safe(p.Status), joined(allStatuses)), "")
	}
	if p.ReviewBy == "" {
		probs.add("review_by", "missing", "every profile must state when its citations need re-verifying")
	} else if !reDate.MatchString(p.ReviewBy) {
		probs.add("review_by", fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(p.ReviewBy)), "")
	}

	if len(p.Citations) == 0 {
		probs.add("citations", "empty", "at least one published instrument must be cited")
	}
	for i, c := range p.Citations {
		p.validateCitation(&probs, i, c)
	}

	if len(p.ControlCatalogs) == 0 {
		probs.add("control_catalogs", "empty", "at least one control catalog must be named")
	}
	for i, c := range p.ControlCatalogs {
		p.validateCatalogReference(&probs, i, c)
	}

	p.validateAssessment(&probs)
	p.validateDeterminations(&probs)
	p.validateScoring(&probs)
	p.validateSubmission(&probs)
	p.validateApplicability(&probs)

	for i, a := range p.Signatures {
		p.validateAttestation(&probs, i, a)
	}

	if !validLongProse(p.PolicyCaveat) {
		probs.add("policy_caveat", "missing or not printable text", "state the policy caveat in substance (docs/policy-caveat.md)")
	}

	if len(p.Sources) == 0 {
		probs.add("sources", "empty", "every retrieved citation needs a hashed source entry")
	}
	for i, s := range p.Sources {
		p.validateHashedReference(&probs, fmt.Sprintf("sources[%d]", i), s)
	}

	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: "obligation profile " + safe(p.Meta.ID), Problems: probs.list}
}

func (p *Profile) validateMeta(probs *problems) {
	if p.Meta.ID == "" {
		probs.add("profile.id", "missing", "")
	} else if !reSlug.MatchString(p.Meta.ID) {
		probs.add("profile.id", fmt.Sprintf("%s is not a lowercase-and-hyphens id", safe(p.Meta.ID)), "")
	}
	if !validProse(p.Meta.Title) {
		probs.add("profile.title", "missing or not printable single-line text", "")
	}
	if !validProse(p.Meta.IssuingAuthority) {
		probs.add("profile.issuing_authority", "missing or not printable single-line text", "")
	}
}

func (p *Profile) validateCitation(probs *problems, i int, c Citation) {
	path := fmt.Sprintf("citations[%d]", i)
	if !validProse(c.ID) {
		probs.add(path+".id", "missing or not printable single-line text", "")
	}
	if !validProse(c.Title) {
		probs.add(path+".title", "missing or not printable single-line text", "")
	}
	if c.EffectiveDate == "" || !reDate.MatchString(c.EffectiveDate) {
		probs.add(path+".effective_date", "missing or not a YYYY-MM-DD date",
			"an undated citation cannot be checked for staleness")
	}
	if c.Role != "" && !oneOf(c.Role, allCitationRoles) {
		probs.add(path+".role", fmt.Sprintf("%s is not one of %s", safe(c.Role), joined(allCitationRoles)), "")
	}
}

func (p *Profile) validateCatalogReference(probs *problems, i int, c CatalogReference) {
	path := fmt.Sprintf("control_catalogs[%d]", i)
	if !validProse(c.Catalog) {
		probs.add(path+".catalog", "missing or not printable single-line text", "")
	}
	if !oneOf(c.RevisionPolicy, allRevisionPolicies) {
		probs.add(path+".revision_policy", fmt.Sprintf("%s is not one of %s",
			safe(c.RevisionPolicy), joined(allRevisionPolicies)), "")
		return
	}
	switch c.RevisionPolicy {
	case "pinned":
		if !validProse(c.Revision) {
			probs.add(path+".revision", "required when revision_policy is pinned", "")
		}
	case RevisionOperatorDetermined:
		if c.Revision != "" {
			probs.add(path+".revision", "forbidden when revision_policy is operator-determined",
				"a pinned revision here is a default wearing a different hat")
		}
	}
}

func (p *Profile) validateAssessment(probs *problems) {
	if !oneOf(p.Assessment.Type, allAssessmentTypes) {
		probs.add("assessment.type", fmt.Sprintf("%s is not one of %s",
			safe(p.Assessment.Type), joined(allAssessmentTypes)), "")
	}
	if len(p.Assessment.SignedBy) == 0 {
		probs.add("assessment.signed_by", "empty", "name at least one role that must sign or affirm")
	}
	for i, s := range p.Assessment.SignedBy {
		if !validProse(s) {
			probs.add(fmt.Sprintf("assessment.signed_by[%d]", i), "not printable single-line text", "")
		}
	}
	if !validProse(p.Assessment.Cadence) {
		probs.add("assessment.cadence", "missing or not printable single-line text", "")
	}
	if p.Assessment.AuditedByIssuer != "" && !oneOf(p.Assessment.AuditedByIssuer, allAuditedByIssuer) {
		probs.add("assessment.audited_by_issuer", fmt.Sprintf("%s is not one of %s",
			safe(p.Assessment.AuditedByIssuer), joined(allAuditedByIssuer)), "")
	}
	if p.Assessment.DocumentationSubmitted != "" && !oneOf(p.Assessment.DocumentationSubmitted, allDocumentationSubs) {
		probs.add("assessment.documentation_submitted", fmt.Sprintf("%s is not one of %s",
			safe(p.Assessment.DocumentationSubmitted), joined(allDocumentationSubs)), "")
	}
}

func (p *Profile) validateDeterminations(probs *problems) {
	if len(p.Determinations.Values) < 2 {
		probs.add("determinations.values", "fewer than two values",
			"a determination vocabulary needs at least a satisfied and an unsatisfied reading")
	}
	seen := map[string]bool{}
	for i, v := range p.Determinations.Values {
		if !validProse(v) {
			probs.add(fmt.Sprintf("determinations.values[%d]", i), "not printable single-line text", "")
			continue
		}
		if seen[v] {
			probs.add("determinations.values", fmt.Sprintf("%s appears twice", safe(v)), "")
		}
		seen[v] = true
	}
	if p.Determinations.UnderstatementValue == "" {
		probs.add("determinations.understatement_value", "missing",
			"name the value automat may write on its own (docs/assessment-reporting.md, Invariant 2)")
	} else if !seen[p.Determinations.UnderstatementValue] {
		probs.add("determinations.understatement_value",
			fmt.Sprintf("%s is not a member of determinations.values", safe(p.Determinations.UnderstatementValue)),
			"the understatement value must be one of the regime's own vocabulary")
	}
}

func (p *Profile) validateScoring(probs *problems) {
	if !oneOf(p.Scoring.Method, allScoringMethods) {
		probs.add("scoring.method", fmt.Sprintf("%s is not one of %s",
			safe(p.Scoring.Method), joined(allScoringMethods)), "")
		return
	}
	switch p.Scoring.Method {
	case "none":
		if p.Scoring.WeightTable != nil {
			probs.add("scoring.weight_table", "forbidden when method is none", "")
		}
	default:
		if p.Scoring.WeightTable == nil {
			probs.add("scoring.weight_table", "required when a scoring method is named",
				"a scoring method with no weight table computes a number from weights that came from nowhere")
		} else {
			p.validateHashedReference(probs, "scoring.weight_table", *p.Scoring.WeightTable)
		}
	}
}

func (p *Profile) validateSubmission(probs *problems) {
	if !validProse(p.Submission.Target) {
		probs.add("submission.target", "missing or not printable single-line text", "")
	}
}

func (p *Profile) validateApplicability(probs *problems) {
	if !validLongProse(p.Applicability.Trigger) {
		probs.add("applicability.trigger", "missing or not printable text", "")
	}
	if len(p.Applicability.Hints) > 32 {
		probs.add("applicability.hints", fmt.Sprintf("%d entries, more than 32", len(p.Applicability.Hints)),
			"hints are a reading aid, not a rule set — keep it short")
	}
	if !p.Applicability.DeclaredByOperator {
		probs.add("applicability.declared_by_operator", "must be true",
			"a profile cannot opt into automatic applicability")
	}
}

func (p *Profile) validateAttestation(probs *problems, i int, a Attestation) {
	path := fmt.Sprintf("signatures[%d]", i)
	if !oneOf(a.Role, allAttestationRoles) {
		probs.add(path+".role", fmt.Sprintf("%s is not one of %s", safe(a.Role), joined(allAttestationRoles)), "")
	}
	if !validProse(a.Identity) {
		probs.add(path+".identity", "missing or not printable single-line text", "")
	}
	if !validLongProse(a.Statement) {
		probs.add(path+".statement", "missing or not printable text", "")
	}
	if !reSHA256.MatchString(a.ContentSHA256) {
		probs.add(path+".content_sha256", "not a lowercase hex SHA-256", "")
	}
	if !reDate.MatchString(a.AttestedAt) {
		probs.add(path+".attested_at", "not a YYYY-MM-DD date", "")
	}
	if a.Signature != nil {
		p.validateSignature(probs, path+".signature", *a.Signature)
	}
}

func (p *Profile) validateSignature(probs *problems, path string, s Signature) {
	if !oneOf(s.Format, allSignatureFormats) {
		probs.add(path+".format", fmt.Sprintf("%s is not one of %s", safe(s.Format), joined(allSignatureFormats)), "")
		return
	}
	switch s.Format {
	case "oidc-identity-bundle":
		if s.IdentityIssuer == "" {
			probs.add(path+".identity_issuer", "required for the keyless form", "")
		}
		if s.KeyID != "" {
			probs.add(path+".key_id", "forbidden for the keyless form", "")
		}
	default:
		if s.KeyID == "" {
			probs.add(path+".key_id", "required for the detached form", "")
		}
		if s.IdentityIssuer != "" {
			probs.add(path+".identity_issuer", "forbidden for the detached form", "")
		}
	}
}

func (p *Profile) validateHashedReference(probs *problems, path string, h HashedReference) {
	if !validProse(h.ID) {
		probs.add(path+".id", "missing or not printable single-line text", "")
	}
	if !reSHA256.MatchString(h.SHA256) {
		probs.add(path+".sha256", "not a lowercase hex SHA-256", "")
	}
}

// Validate checks the determinations document against
// schema/operator-determinations-v1.schema.json's shape-only constraints —
// everything that does not require knowing which obligation profile this
// document is for. ValidateAgainst covers the rest (vocabulary, the
// revision-policy requirement) once a profile is in hand.
//
// Reports every problem in one pass, same reasoning as Profile.Validate.
func (d *Determinations) Validate() error {
	var probs problems

	if d.SchemaVersion == "" {
		probs.add("schema_version", "missing", "set it, e.g. \"1.0.0\"")
	} else if !reSemver.MatchString(d.SchemaVersion) {
		probs.add("schema_version", fmt.Sprintf("%s is not semver", safe(d.SchemaVersion)), "use MAJOR.MINOR.PATCH")
	}

	if len(d.List) == 0 {
		probs.add("determinations", "empty", "at least one determination must be given")
	}
	seenObjective := map[string]string{}
	seenID := map[string]bool{}
	for i, det := range d.List {
		path := fmt.Sprintf("determinations[%d]", i)
		if !validRoundTripID(det.ID) {
			probs.add(path+".id", fmt.Sprintf("%s is not a round-trip id", safe(det.ID)),
				"letters, digits, dot, dash, underscore only — CLAUDE.md rule 8")
		} else if seenID[det.ID] {
			probs.add(path+".id", fmt.Sprintf("%s appears twice", safe(det.ID)), "")
		}
		seenID[det.ID] = true

		if len(det.Objectives) == 0 {
			probs.add(path+".objectives", "empty", "name at least one objective this determination covers")
		}
		for j, obj := range det.Objectives {
			if !validProse(obj) {
				probs.add(fmt.Sprintf("%s.objectives[%d]", path, j), "not printable single-line text", "")
				continue
			}
			if owner, ok := seenObjective[obj]; ok && owner != det.ID {
				probs.add(fmt.Sprintf("%s.objectives[%d]", path, j),
					fmt.Sprintf("%s is also claimed by determination %s", safe(obj), safe(owner)),
					"one objective may not carry two conflicting determinations")
			}
			seenObjective[obj] = det.ID
		}

		if !validProse(det.Value) {
			probs.add(path+".value", "missing or not printable single-line text", "")
		}
		if !validLongProse(det.Statement) {
			probs.add(path+".statement", "missing or not printable text",
				"a determination needs a statement a reader can evaluate, not a bare value")
		}
		if det.Date == "" || !reDate.MatchString(det.Date) {
			probs.add(path+".date", "missing or not a YYYY-MM-DD date", "")
		}
		if !validProse(det.ResponsibleParty) {
			probs.add(path+".responsible_party", "missing or not printable single-line text", "")
		}
	}

	if d.RevisionDetermination != nil {
		rd := d.RevisionDetermination
		if !validProse(rd.Catalog) {
			probs.add("revision_determination.catalog", "missing or not printable single-line text", "")
		}
		if !validProse(rd.Revision) {
			probs.add("revision_determination.revision", "missing or not printable single-line text", "")
		}
		if !validProse(rd.DeterminedBy) {
			probs.add("revision_determination.determined_by", "missing or not printable single-line text", "")
		}
		if rd.DeterminedAt == "" || !reDate.MatchString(rd.DeterminedAt) {
			probs.add("revision_determination.determined_at", "missing or not a YYYY-MM-DD date", "")
		}
		if !validLongProse(rd.Statement) {
			probs.add("revision_determination.statement", "missing or not printable text", "")
		}
	}

	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: "operator determinations", Problems: probs.list}
}

// ValidateAgainst checks the determinations document against the specific
// obligation profile it is meant to accompany: every determination's value
// must be a member of the profile's own vocabulary (schema/
// operator-determinations-v1.schema.json's own comment: "validated against
// the named profile's vocabulary at load time"), and a profile whose
// control-catalog revision is left operator-determined must be accompanied
// by a RevisionDetermination — automat ships no default for either, since a
// default here would silently pick an institution's compliance posture for
// it.
func (d *Determinations) ValidateAgainst(p *Profile) error {
	var probs problems

	for i, det := range d.List {
		if det.Value != "" && !oneOf(det.Value, p.Determinations.Values) {
			probs.add(fmt.Sprintf("determinations[%d].value", i),
				fmt.Sprintf("%s is not a member of %s's determination vocabulary (%s)",
					safe(det.Value), safe(p.Meta.ID), joined(p.Determinations.Values)),
				"spell the value exactly as the obligation profile's determinations.values names it")
		}
	}

	for _, cat := range p.ControlCatalogs {
		if cat.RevisionPolicy != RevisionOperatorDetermined {
			continue
		}
		if d.RevisionDetermination == nil {
			probs.add("revision_determination",
				fmt.Sprintf("missing, but %s's catalog %s leaves its revision operator-determined",
					safe(p.Meta.ID), safe(cat.Catalog)),
				"automat ships no default revision; state which one applies and why")
			continue
		}
		if d.RevisionDetermination.Catalog != cat.Catalog {
			probs.add("revision_determination.catalog",
				fmt.Sprintf("%s does not match %s's operator-determined catalog %s",
					safe(d.RevisionDetermination.Catalog), safe(p.Meta.ID), safe(cat.Catalog)), "")
		}
	}

	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: "operator determinations against profile " + safe(p.Meta.ID), Problems: probs.list}
}
