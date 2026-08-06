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
//
// Every order must be monotone: the resolved value never permits behavior that
// either input forbade. That is the property the union code is tested against,
// and it is why there is no "first wins" or "last wins" option.
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
	// OrderSetUnion means the value is a set of prohibited items — blocked
	// ports, blocked action patterns — so the union of both sets is stricter.
	OrderSetUnion ParamOrder = "set-union"
	// OrderSetIntersect means the value is a set of permitted items —
	// authorized ports — so the intersection of both sets is stricter.
	OrderSetIntersect ParamOrder = "set-intersect"
)

// AllParamOrders lists every valid order in canonical order.
var AllParamOrders = []ParamOrder{OrderMin, OrderMax, OrderExact, OrderSetUnion, OrderSetIntersect}

func (o ParamOrder) valid() bool {
	for _, v := range AllParamOrders {
		if v == o {
			return true
		}
	}
	return false
}

// IsSet reports whether the order treats the value as a set of members rather
// than a scalar.
func (o ParamOrder) IsSet() bool {
	return o == OrderSetUnion || o == OrderSetIntersect
}

// BindingProvenance says who asserts that a Config rule enforces a control.
//
// The distinction is load-bearing for review, not decoration: an aws-mapping
// binding is vouched for by a published AWS mapping recorded in
// artifact.sources and is mechanically generated, whereas a curated binding is
// this project's own judgment and must say why. `verify` and the enforcement
// breakdown can therefore report how much of a control set rests on automat's
// own claims rather than AWS's.
type BindingProvenance string

// The binding provenances.
const (
	// ProvenanceAWSMapping means a published AWS mapping associates this rule
	// with this control. Bindings of this kind are generated from the mapping
	// and must never be hand-edited.
	ProvenanceAWSMapping BindingProvenance = "aws-mapping"
	// ProvenanceCurated means this project asserts the association itself. A
	// curated binding must carry a Rationale.
	ProvenanceCurated BindingProvenance = "curated"
)

// AllBindingProvenances lists every valid provenance in canonical order.
var AllBindingProvenances = []BindingProvenance{ProvenanceAWSMapping, ProvenanceCurated}

func (b BindingProvenance) valid() bool {
	for _, v := range AllBindingProvenances {
		if v == b {
			return true
		}
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
	// RegionDenyExemptServices are the service namespaces a REGION Deny must not
	// cover, as catalog DATA rather than a list compiled into the binary.
	//
	// Globally addressed services answer on endpoints AWS reports as us-east-1, so
	// a Deny on every action outside a region allowlist denies every IAM, STS, and
	// Organizations call in the account — including the operator's own ability to
	// undo it. Getting the list wrong bricks an account, which is the argument for
	// it being reviewable content rather than a var in a package: the same argument
	// ExemptPrincipals rests on, and a list only the binary knows is a control
	// whose scope cannot be reviewed or corrected without a release.
	//
	// ARTIFACT-LEVEL rather than per control, and not for tidiness. Its scope IS
	// the artifact: two controls in one document carrying different lists would
	// have no coherent reading. Per-control also made this an SCP block on a
	// control that denies nothing, which a baseline-protection control is not
	// allowed to be — an AWS fact about which endpoints answer where is not a Deny
	// and must not be shaped like one.
	//
	// INTERSECTED under union, and that is forced rather than chosen: a Deny over
	// NotAction[a:*] concatenated with a Deny over NotAction[b:*] denies everything
	// except a∩b, so a merge that unioned these would describe something the
	// rendered policy does not do.
	//
	// Deliberately NOT required alongside a region allowlist. The control set
	// stating an AWS fact need not be the one restricting regions — automat's own
	// baseline-protection supplies this list and constrains no regions. The pairing
	// is a plan-time invariant instead: if any input constrains regions and none
	// supplies this list, the packer refuses, because a fallback is the compiled-in
	// list with extra steps.
	RegionDenyExemptServices []string `json:"region_deny_exempt_services,omitempty"`
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
//
// There is deliberately no NotAction field. A Deny over NotAction denies
// everything it does not name, so two such fragments concatenate into a
// deny-all and the safe-concatenation property DESIGN §9 relies on is lost. The
// legitimate uses of that shape are the region and service allowlists, which are
// their own intersected fields so the SCP packer emits the NotAction form rather
// than a catalog author.
type SCPStatement struct {
	Sid       string    `json:"sid"`
	Effect    string    `json:"effect"`
	Action    []string  `json:"action"`
	Resource  []string  `json:"resource,omitempty"`
	Condition Condition `json:"condition,omitempty"`
	// ExemptPrincipals are the principals the packer must exempt from this
	// Deny. A list rather than the single boolean this replaced: a real
	// deployment has more than one legitimate hole in a baseline-protection
	// Deny (a break-glass role, a central-IT audit role), and a catalog that
	// cannot name them forces the operator to weaken the Deny itself instead.
	//
	// This is the one field in a catalog that widens a policy, so it is the one
	// field whose union rule is intersection rather than concatenation: see
	// ExemptPrincipals.
	ExemptPrincipals ExemptPrincipals `json:"exempt_principals,omitempty"`
}

// ExemptPrincipals is a statement's exemption list.
//
// Under union these lists are INTERSECTED, not concatenated. Every other field
// in an SCP fragment gets stricter as control sets merge; an exemption is the
// only thing that gets *looser*, so concatenating them would let adding a
// control set widen the result — the exact direction DESIGN §9's monotonicity
// property forbids. Intersecting means an exemption survives only if every
// control set that constrains the statement agrees to it.
type ExemptPrincipals []ExemptPrincipal

// ExemptPrincipal is one hole in a Deny, with the reason it exists.
type ExemptPrincipal struct {
	// Principal is either AutomationRolePlaceholder or a literal IAM role ARN.
	Principal string `json:"principal"`
	// Reason says why this principal must be exempt. Required: an unexplained
	// exemption is indistinguishable from an escape hatch, and a reviewer of a
	// baseline-protection catalog is reading for precisely that.
	Reason string `json:"reason"`
}

// AutomationRolePlaceholder stands for automat's own in-account automation role,
// whose ARN is not known until vend time. The packer materializes it; a catalog
// author writes the placeholder.
//
// Named "placeholder" rather than "token" because gosec's G101 reads a constant
// named *Token holding a string literal as a hardcoded credential. It was a
// false positive, but the accurate word costs nothing and a //nolint here would
// be one more suppression a future auditor has to re-triage.
const AutomationRolePlaceholder = "automat:automation-role"

// MaxExemptPrincipals caps a statement's exemption list.
//
// Not an arbitrary limit: each entry is a hole in a preventive control, the list
// is rendered into an IAM condition with a per-policy character budget (DESIGN
// §16's 5120-character SCP quota), and a catalog needing more than a handful of
// exemptions is describing a Deny that does not hold. A hard error is better
// than a policy that silently stops fitting.
const MaxExemptPrincipals = 8

// IsAutomationRole reports whether the entry is the symbolic automation-role
// token rather than a literal ARN.
func (e ExemptPrincipal) IsAutomationRole() bool { return e.Principal == AutomationRolePlaceholder }

// Condition is an IAM condition block: operator -> condition key -> values.
//
// Values are always modeled as a slice even when IAM permits a bare string, so
// that canonicalization has one shape to hash.
type Condition map[string]map[string][]string

// ConfigRule is one AWS Config managed rule bound to a control, with the
// provenance of that binding.
type ConfigRule struct {
	Identifier string            `json:"identifier"`
	Name       string            `json:"name,omitempty"`
	Provenance BindingProvenance `json:"provenance"`
	// Rationale says why this rule is bound to this control. Required when
	// Provenance is ProvenanceCurated, where no upstream mapping vouches for
	// the association.
	Rationale     string                   `json:"rationale,omitempty"`
	Parameters    map[string]RuleParameter `json:"parameters,omitempty"`
	ResourceTypes []string                 `json:"resource_types,omitempty"`
}

// DefaultSetSeparator splits a set-valued parameter into its members when the
// parameter does not say otherwise. AWS Config managed rules that take lists
// take them comma-separated.
const DefaultSetSeparator = ","

// RuleParameter is a rule parameter value plus its union order.
type RuleParameter struct {
	Value string     `json:"value"`
	Order ParamOrder `json:"order"`
	// SetSeparator splits Value into set members, for the set-valued orders
	// only. Empty means DefaultSetSeparator.
	SetSeparator string `json:"set_separator,omitempty"`
}

// Separator returns the separator that splits Value into members.
func (p RuleParameter) Separator() string {
	if p.SetSeparator != "" {
		return p.SetSeparator
	}
	return DefaultSetSeparator
}

// Members splits a set-valued parameter into its members, trimmed of
// surrounding space and deduplicated, in sorted order. It returns nil for
// scalar orders — a scalar has a value, not members.
func (p RuleParameter) Members() []string {
	if !p.Order.IsSet() {
		return nil
	}
	sep := p.Separator()
	parts := strings.Split(p.Value, sep)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if m := strings.TrimSpace(part); m != "" {
			out = append(out, m)
		}
	}
	return sortedUnique(out)
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
