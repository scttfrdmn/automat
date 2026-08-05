// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Problem is a single validation failure.
//
// Errors in automat are values with remediation text (CLAUDE.md rule 7): Path
// says where, Message says what is wrong, and Fix says what to change. A
// validation failure a human cannot act on is a bug in the validator.
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

// ValidationError collects every problem found in one pass.
//
// Validation reports all problems rather than stopping at the first, because a
// catalog author fixing a compile wants the whole list, not one line at a time.
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

// Unwrap exposes the problems to errors.Is/As traversal.
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

// Regexes mirror the patterns in schema/control-artifact-v1.schema.json. The
// schema conformance test is what keeps them in step.
var (
	reSemver     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reArtifactID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	reSHA256     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reTimestamp  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	reRuleID     = regexp.MustCompile(`^[A-Z0-9_]+$`)
	reRuleName   = regexp.MustCompile(`^[a-z0-9-]+$`)
	reRegion     = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	reService    = regexp.MustCompile(`^[a-z0-9-]+$`)
	reSid        = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	reTemplate   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.md$`)
)

// Validate checks the artifact against the schema's constraints and returns a
// *ValidationError listing every problem found.
//
// It does not verify the content hash; that is VerifyContentHash, kept separate
// so a freshly compiled artifact can be validated before its hash is set.
func (a *Artifact) Validate() error {
	var p problems

	if a.SchemaVersion == "" {
		p.add("schema_version", "missing", "set it to "+SchemaVersion)
	} else if !reSemver.MatchString(a.SchemaVersion) {
		p.add("schema_version", fmt.Sprintf("%q is not semver", a.SchemaVersion), "use MAJOR.MINOR.PATCH, e.g. "+SchemaVersion)
	} else if major := majorOf(a.SchemaVersion); major != majorOf(SchemaVersion) {
		p.add("schema_version", fmt.Sprintf("major version %s is not supported by this build", major),
			"this build understands control-artifact schema "+majorOf(SchemaVersion)+".x; upgrade automat or recompile the artifact")
	}

	a.Meta.validate(&p)
	a.Controls.validate(&p)

	if len(p.list) == 0 {
		return nil
	}
	subject := "control artifact"
	if a.Meta.ID != "" {
		subject = fmt.Sprintf("control artifact %q", a.Meta.ID)
	}
	return &ValidationError{Subject: subject, Problems: p.list}
}

func majorOf(semver string) string {
	if i := strings.IndexByte(semver, '.'); i > 0 {
		return semver[:i]
	}
	return semver
}

func (m *Meta) validate(p *problems) {
	if m.ID == "" {
		p.add("artifact.id", "missing", "give the artifact a stable id, e.g. \"cmmc-l1\"")
	} else if !reArtifactID.MatchString(m.ID) {
		p.add("artifact.id", fmt.Sprintf("%q is not a valid id", m.ID),
			"use 2-64 chars of lowercase letters, digits, and hyphens, starting and ending alphanumeric; the id becomes part of SCP names and account tags")
	}
	if m.Title == "" {
		p.add("artifact.title", "missing", "give the artifact a human-readable title")
	}
	if m.CompiledAt == "" {
		p.add("artifact.compiled_at", "missing", "set it to the compile time in RFC 3339 UTC, e.g. 2026-08-04T00:00:00Z")
	} else if !reTimestamp.MatchString(m.CompiledAt) {
		p.add("artifact.compiled_at", fmt.Sprintf("%q is not second-precision UTC RFC 3339", m.CompiledAt),
			"use the form 2026-08-04T00:00:00Z; offsets and sub-second precision would break deterministic hashing")
	}
	if m.ContentHash == "" {
		p.add("artifact.content_sha256", "missing", "call SetContentHash before writing the artifact")
	} else if !reSHA256.MatchString(m.ContentHash) {
		p.add("artifact.content_sha256", fmt.Sprintf("%q is not a lowercase hex SHA-256", m.ContentHash),
			"expected 64 lowercase hex characters")
	}

	if len(m.Sources) == 0 {
		p.add("artifact.sources", "empty",
			"record at least one source with its sha256; provenance of the compile is not optional")
	}
	for i, s := range m.Sources {
		path := fmt.Sprintf("artifact.sources[%d]", i)
		if _, _, err := s.kindKey(); err != nil {
			p.add(path, err.Error(),
				"set exactly one of catalog (authoritative control text), mapping (enforcement mapping), or artifact (an input artifact, for unions)")
		}
		if s.SHA256 == "" {
			p.add(path+".sha256", "missing",
				"hash the source bytes you actually consumed; without it the compile is unprovenanced")
		} else if !reSHA256.MatchString(s.SHA256) {
			p.add(path+".sha256", fmt.Sprintf("%q is not a lowercase hex SHA-256", s.SHA256), "expected 64 lowercase hex characters")
		}
		if s.RetrievedAt != "" && !reTimestamp.MatchString(s.RetrievedAt) {
			p.add(path+".retrieved_at", fmt.Sprintf("%q is not second-precision UTC RFC 3339", s.RetrievedAt),
				"use the form 2026-08-04T00:00:00Z")
		}
	}
}

func (cs Controls) validate(p *problems) {
	if len(cs) == 0 {
		p.add("controls", "empty", "an artifact with no controls enforces nothing; add at least one control")
		return
	}
	seen := make(map[string]int, len(cs))
	for i := range cs {
		path := fmt.Sprintf("controls[%d]", i)
		if id := cs[i].ID; id != "" {
			if prev, dup := seen[id]; dup {
				p.add(path+".id", fmt.Sprintf("duplicate control id %q (first seen at controls[%d])", id, prev),
					"control ids must be unique within an artifact; merge the two entries or correct the id")
			} else {
				seen[id] = i
			}
			path = fmt.Sprintf("controls[%s]", id)
		}
		cs[i].validate(p, path)
	}
}

func (c *Control) validate(p *problems, path string) {
	if c.ID == "" {
		p.add(path+".id", "missing", "use the control's authoritative identifier, e.g. \"AC.L1-b.1.i\"")
	}
	if c.Title == "" {
		p.add(path+".title", "missing", "give the control a human-readable title")
	}

	if len(c.Enforcement) == 0 {
		p.add(path+".enforcement", "missing",
			"declare how automat handles this control: one or more of scp, config-rule, procedural, baseline-protection; "+
				"a control with no enforcement class would be silently dropped from every report")
	}
	seenClass := make(map[EnforcementClass]bool, len(c.Enforcement))
	for _, e := range c.Enforcement {
		if !e.valid() {
			p.add(path+".enforcement", fmt.Sprintf("%q is not a known enforcement class", e),
				"use one or more of scp, config-rule, procedural, baseline-protection")
			continue
		}
		if seenClass[e] {
			p.add(path+".enforcement", fmt.Sprintf("%q appears more than once", e), "remove the duplicate")
		}
		seenClass[e] = true
	}

	// Each declared class must bring the payload that makes it actionable.
	// Without this, a control could claim SCP enforcement and enforce nothing.
	wantsSCP := c.Enforces(EnforcementSCP) || c.Enforces(EnforcementBaselineProtection)
	switch {
	case wantsSCP && c.SCP == nil:
		p.add(path+".scp", "missing but enforcement declares scp or baseline-protection",
			"add the scp fragment, or drop the class from enforcement")
	case !wantsSCP && c.SCP != nil:
		p.add(path+".scp", "present but enforcement declares neither scp nor baseline-protection",
			"add \"scp\" to enforcement, or remove the scp fragment; as written the fragment would never be attached")
	}
	if c.Enforces(EnforcementConfigRule) && len(c.ConfigRules) == 0 {
		p.add(path+".config_rules", "missing but enforcement declares config-rule",
			"add at least one Config rule, or drop \"config-rule\" from enforcement")
	}
	if !c.Enforces(EnforcementConfigRule) && len(c.ConfigRules) > 0 {
		p.add(path+".config_rules", "present but enforcement does not declare config-rule",
			"add \"config-rule\" to enforcement, or remove the rules; as written they would never be deployed")
	}
	if c.Enforces(EnforcementProcedural) && c.Attestation == nil {
		p.add(path+".attestation", "missing but enforcement declares procedural",
			"add an attestation stub (template + frequency), or drop \"procedural\" from enforcement; "+
				"a procedural control with no stub produces no evidence")
	}
	if !c.Enforces(EnforcementProcedural) && c.Attestation != nil {
		p.add(path+".attestation", "present but enforcement does not declare procedural",
			"add \"procedural\" to enforcement, or remove the attestation stub")
	}

	for k, v := range c.Crosswalk {
		if k == "" {
			p.add(path+".crosswalk", "has an empty framework key", "key each entry by framework, e.g. \"800-171r2\"")
		}
		if v == "" {
			p.add(fmt.Sprintf("%s.crosswalk[%q]", path, k), "empty identifier",
				"give the equivalent control id in that framework, or omit the key")
		}
	}

	if c.SCP != nil {
		c.SCP.validate(p, path+".scp")
	}
	for i := range c.ConfigRules {
		c.ConfigRules[i].validate(p, fmt.Sprintf("%s.config_rules[%d]", path, i))
	}
	if c.Attestation != nil {
		c.Attestation.validate(p, path+".attestation")
	}
}

func (s *SCP) validate(p *problems, path string) {
	if len(s.Statements) == 0 && len(s.RegionAllowlist) == 0 && len(s.ServiceAllowlist) == 0 {
		p.add(path, "has no statements and no allowlists",
			"add at least one statement, region_allowlist, or service_allowlist")
	}
	seenSid := make(map[string]bool, len(s.Statements))
	for i := range s.Statements {
		st := &s.Statements[i]
		spath := fmt.Sprintf("%s.statements[%d]", path, i)
		if st.Sid == "" {
			p.add(spath+".sid", "missing", "give the statement a unique alphanumeric Sid; the SCP packer uses it to dedupe")
		} else {
			if !reSid.MatchString(st.Sid) {
				p.add(spath+".sid", fmt.Sprintf("%q is not alphanumeric", st.Sid),
					"IAM allows only letters and digits in a Sid")
			}
			if seenSid[st.Sid] {
				p.add(spath+".sid", fmt.Sprintf("duplicate Sid %q within this control", st.Sid), "Sids must be unique per control")
			}
			seenSid[st.Sid] = true
			spath = fmt.Sprintf("%s.statements[%s]", path, st.Sid)
		}

		switch st.Effect {
		case "Deny":
			// The preferred form.
		case "Allow":
			// Permitted, but Allow in an SCP only widens what a parent SCP
			// already permits and does not compose under union, so flag it.
			p.add(spath+".effect", "is \"Allow\", which does not compose under union",
				"prefer Deny fragments; union of control sets must be an intersection of permitted behavior (DESIGN §9). "+
					"If an Allow is genuinely required, document why in the catalog's mapping notes")
		case "":
			p.add(spath+".effect", "missing", "set it to \"Deny\" (preferred) or \"Allow\"")
		default:
			p.add(spath+".effect", fmt.Sprintf("%q is not a valid effect", st.Effect), "use \"Deny\" or \"Allow\"")
		}

		if len(st.Action) == 0 && len(st.NotAction) == 0 {
			p.add(spath, "has neither action nor not_action", "list the actions this statement covers")
		}
		if len(st.Action) > 0 && len(st.NotAction) > 0 {
			p.add(spath, "sets both action and not_action",
				"IAM evaluates these very differently; pick one so the statement's meaning is unambiguous")
		}
		for op, keys := range st.Condition {
			if op == "" {
				p.add(spath+".condition", "has an empty condition operator", "use an IAM operator, e.g. \"StringNotEquals\"")
			}
			for k, vals := range keys {
				if k == "" {
					p.add(fmt.Sprintf("%s.condition[%q]", spath, op), "has an empty condition key",
						"use an IAM condition key, e.g. \"aws:PrincipalArn\"")
				}
				if len(vals) == 0 {
					p.add(fmt.Sprintf("%s.condition[%q][%q]", spath, op, k), "has no values",
						"give at least one value, or remove the key")
				}
			}
		}
	}

	for i, r := range s.RegionAllowlist {
		if !reRegion.MatchString(r) {
			p.add(fmt.Sprintf("%s.region_allowlist[%d]", path, i), fmt.Sprintf("%q is not a region code", r),
				"use codes like us-east-1 or eu-west-2")
		}
	}
	for i, sv := range s.ServiceAllowlist {
		if !reService.MatchString(sv) {
			p.add(fmt.Sprintf("%s.service_allowlist[%d]", path, i), fmt.Sprintf("%q is not a service namespace", sv),
				"use IAM service namespaces like s3, ec2, or organizations")
		}
	}
}

func (r *ConfigRule) validate(p *problems, path string) {
	if r.Identifier == "" {
		p.add(path+".identifier", "missing",
			"use the AWS Config managed rule source identifier, e.g. IAM_PASSWORD_POLICY")
	} else if !reRuleID.MatchString(r.Identifier) {
		p.add(path+".identifier", fmt.Sprintf("%q is not a managed rule identifier", r.Identifier),
			"managed rule identifiers are uppercase with underscores, e.g. ACCESS_KEYS_ROTATED")
	}
	if r.Name != "" && !reRuleName.MatchString(r.Name) {
		p.add(path+".name", fmt.Sprintf("%q is not a valid rule name", r.Name),
			"deployed rule names are lowercase with hyphens, e.g. access-keys-rotated")
	}
	names := make([]string, 0, len(r.Parameters))
	for k := range r.Parameters {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		param := r.Parameters[k]
		ppath := fmt.Sprintf("%s.parameters[%q]", path, k)
		if k == "" {
			p.add(path+".parameters", "has an empty parameter name", "name each parameter as the rule expects it")
		}
		if param.Order == "" {
			p.add(ppath+".order", "missing",
				"declare min, max, or exact; union needs the order to resolve two sets binding this parameter, "+
					"and guessing is not allowed (DESIGN §9)")
		} else if !param.Order.valid() {
			p.add(ppath+".order", fmt.Sprintf("%q is not a valid order", param.Order),
				"use min (smaller is stricter), max (larger is stricter), or exact (conflict is a hard error)")
		}
	}
}

func (at *Attestation) validate(p *problems, path string) {
	if at.Template == "" {
		p.add(path+".template", "missing", "name the attestation template file, e.g. \"media-sanitization.md\"")
	} else if !reTemplate.MatchString(at.Template) {
		p.add(path+".template", fmt.Sprintf("%q is not a valid template name", at.Template),
			"use a lowercase hyphenated .md filename, e.g. \"physical-access.md\"")
	}
	if at.Frequency == "" {
		p.add(path+".frequency", "missing", "set the attestation cadence, one of: "+strings.Join(AllFrequencies, ", "))
	} else {
		ok := false
		for _, f := range AllFrequencies {
			if at.Frequency == f {
				ok = true
				break
			}
		}
		if !ok {
			p.add(path+".frequency", fmt.Sprintf("%q is not a valid frequency", at.Frequency),
				"use one of: "+strings.Join(AllFrequencies, ", "))
		}
	}
}

// AsValidationError extracts a *ValidationError from err, if there is one.
func AsValidationError(err error) (*ValidationError, bool) {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
