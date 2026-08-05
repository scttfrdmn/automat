// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"fmt"
	"sort"
	"strings"
)

// SchemaVersion is the control artifact schema version this build emits.
const SchemaVersion = "1.0.0"

// ZeroHash is the previous_sha256 value of the first record in an evidence
// chain: 64 zeros, meaning "nothing precedes this".
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// EnforcementClass is how automat enforces or monitors a control.
type EnforcementClass string

// The enforcement classes. These are a closed set; `verify` reports its
// enforcement-class breakdown over exactly these (DESIGN §12).
const (
	// EnforcementSCP is preventive: enforced by a service control policy.
	EnforcementSCP EnforcementClass = "scp"
	// EnforcementConfigRule is detective: monitored by AWS Config.
	EnforcementConfigRule EnforcementClass = "config-rule"
	// EnforcementProcedural requires a documented human process and produces
	// an attestation stub, not enforcement.
	EnforcementProcedural EnforcementClass = "procedural"
	// EnforcementBaselineProtection is an SCP that guards automat's own
	// baseline against tampering (DESIGN §10).
	EnforcementBaselineProtection EnforcementClass = "baseline-protection"
)

// AllEnforcementClasses lists every valid class in canonical order.
var AllEnforcementClasses = []EnforcementClass{
	EnforcementSCP,
	EnforcementConfigRule,
	EnforcementProcedural,
	EnforcementBaselineProtection,
}

func (e EnforcementClass) valid() bool {
	for _, c := range AllEnforcementClasses {
		if c == e {
			return true
		}
	}
	return false
}

// ParamOrder is the partial order used to resolve a Config rule parameter when
// two control sets bind the same parameter during union (DESIGN §9).
type ParamOrder string

// The parameter orders.
const (
	// OrderMin means the smaller value is the stricter one.
	OrderMin ParamOrder = "min"
	// OrderMax means the larger value is the stricter one.
	OrderMax ParamOrder = "max"
	// OrderExact means there is no ordering: conflicting values are a hard
	// error demanding an explicit override. Never guess.
	OrderExact ParamOrder = "exact"
)

func (o ParamOrder) valid() bool {
	switch o {
	case OrderMin, OrderMax, OrderExact:
		return true
	}
	return false
}

// Artifact is a compiled, frozen control set.
//
// It is the document automat interprets at vend time; automat never interprets
// raw upstream catalog formats there.
type Artifact struct {
	SchemaVersion string   `json:"schema_version"`
	Meta          Meta     `json:"artifact"`
	Controls      Controls `json:"controls"`
}

// Meta is an artifact's identity and provenance.
type Meta struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Sources     Sources `json:"sources"`
	CompiledAt  string  `json:"compiled_at"`
	ContentHash string  `json:"content_sha256"`
}

// Sources is the provenance of a compile.
type Sources []Source

// Source is one compile input. Exactly one of Catalog, Mapping, or Artifact is
// set, naming the kind of input.
type Source struct {
	Catalog     string `json:"catalog,omitempty"`
	Mapping     string `json:"mapping,omitempty"`
	Artifact    string `json:"artifact,omitempty"`
	Version     string `json:"version,omitempty"`
	RetrievedAt string `json:"retrieved_at,omitempty"`
	URI         string `json:"uri,omitempty"`
	SHA256      string `json:"sha256"`
	Note        string `json:"note,omitempty"`
}

// kindKey returns the discriminator and its value, for sorting and validation.
func (s Source) kindKey() (kind, value string, err error) {
	set := 0
	if s.Catalog != "" {
		set, kind, value = set+1, "catalog", s.Catalog
	}
	if s.Mapping != "" {
		set, kind, value = set+1, "mapping", s.Mapping
	}
	if s.Artifact != "" {
		set, kind, value = set+1, "artifact", s.Artifact
	}
	switch set {
	case 1:
		return kind, value, nil
	case 0:
		return "", "", fmt.Errorf("source sets none of catalog/mapping/artifact")
	default:
		return "", "", fmt.Errorf("source sets %d of catalog/mapping/artifact; exactly one is allowed", set)
	}
}

// Controls is a list of controls.
type Controls []Control

// Control is one requirement plus how automat handles it.
type Control struct {
	ID          string             `json:"id"`
	Title       string             `json:"title"`
	Statement   string             `json:"statement,omitempty"`
	Crosswalk   map[string]string  `json:"crosswalk,omitempty"`
	Enforcement []EnforcementClass `json:"enforcement"`
	SCP         *SCP               `json:"scp,omitempty"`
	ConfigRules []ConfigRule       `json:"config_rules,omitempty"`
	Attestation *Attestation       `json:"attestation,omitempty"`
}

// Enforces reports whether the control carries the given enforcement class.
func (c Control) Enforces(class EnforcementClass) bool {
	for _, e := range c.Enforcement {
		if e == class {
			return true
		}
	}
	return false
}

// SCP holds a control's preventive policy fragments and allowlists.
//
// Deny-style statements are strongly preferred: they concatenate safely under
// union, whereas allowlists must be intersected (DESIGN §9).
type SCP struct {
	Statements       []SCPStatement `json:"statements"`
	RegionAllowlist  []string       `json:"region_allowlist,omitempty"`
	ServiceAllowlist []string       `json:"service_allowlist,omitempty"`
}

// SCPStatement is a single policy statement fragment.
type SCPStatement struct {
	Sid       string    `json:"sid"`
	Effect    string    `json:"effect"`
	Action    []string  `json:"action"`
	NotAction []string  `json:"not_action,omitempty"`
	Resource  []string  `json:"resource,omitempty"`
	Condition Condition `json:"condition,omitempty"`
	// ExemptAutomationRole marks statements the packer must condition so they
	// do not lock out automat's own in-account automation role. The role ARN is
	// not known until vend time, hence a marker rather than a literal ARN.
	ExemptAutomationRole bool `json:"exempt_automation_role,omitempty"`
}

// Condition is an IAM condition block: operator -> condition key -> values.
//
// Values are always modeled as a slice even when IAM permits a bare string, so
// that canonicalization has one shape to hash.
type Condition map[string]map[string][]string

// ConfigRule is one AWS Config managed rule.
type ConfigRule struct {
	Identifier    string                   `json:"identifier"`
	Name          string                   `json:"name,omitempty"`
	Parameters    map[string]RuleParameter `json:"parameters,omitempty"`
	ResourceTypes []string                 `json:"resource_types,omitempty"`
}

// RuleParameter is a rule parameter value plus its union order.
type RuleParameter struct {
	Value string     `json:"value"`
	Order ParamOrder `json:"order"`
}

// Attestation describes a procedural control's stub.
type Attestation struct {
	Template  string `json:"template"`
	Frequency string `json:"frequency"`
	Guidance  string `json:"guidance,omitempty"`
}

// AllFrequencies lists the valid attestation frequencies.
var AllFrequencies = []string{"annual", "semiannual", "quarterly", "monthly", "on-change", "continuous"}

// EnforcementBreakdown counts controls by enforcement class.
//
// A control counts once per class it carries, so the counts may sum to more
// than Total. This is what `verify` prints to state the tool's own limits
// (DESIGN §12) — the honesty is the point, so Total is reported alongside.
type EnforcementBreakdown struct {
	Total   int                      `json:"total"`
	ByClass map[EnforcementClass]int `json:"by_class"`
}

// Breakdown computes the enforcement-class breakdown over the artifact.
func (a *Artifact) Breakdown() EnforcementBreakdown {
	b := EnforcementBreakdown{
		Total:   len(a.Controls),
		ByClass: make(map[EnforcementClass]int, len(AllEnforcementClasses)),
	}
	for _, class := range AllEnforcementClasses {
		b.ByClass[class] = 0
	}
	for _, c := range a.Controls {
		for _, e := range c.Enforcement {
			b.ByClass[e]++
		}
	}
	return b
}

// String renders the breakdown in the phrasing DESIGN §12 requires: what this
// tool enforces, what it monitors, and what it cannot do for you.
func (b EnforcementBreakdown) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d controls total", b.Total)
	classes := make([]EnforcementClass, 0, len(b.ByClass))
	for class := range b.ByClass {
		classes = append(classes, class)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	for _, class := range classes {
		fmt.Fprintf(&sb, "; %s: %d", class, b.ByClass[class])
	}
	return sb.String()
}
