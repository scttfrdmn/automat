// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

// Result is an assessment-result document
// (schema/assessment-result-v1.schema.json) — the canonical output every
// human-facing render draws from, never authored independently
// (docs/assessment-reporting.md, "Outputs").
type Result struct {
	SchemaVersion  string         `json:"schema_version"`
	RenderedAt     string         `json:"rendered_at"`
	ToolVersion    string         `json:"tool_version"`
	Account        ResultAccount  `json:"account"`
	Profile        DocRef         `json:"profile"`
	Artifact       DocRef         `json:"artifact"`
	Determinations *DocRef        `json:"determinations,omitempty"`
	Objectives     []ObjectiveRow `json:"objectives"`
	L1Summary      L1Summary      `json:"l1_summary"`
	PolicyCaveat   string         `json:"policy_caveat"`
}

// ResultAccount names the account and its operator-stated scope.
type ResultAccount struct {
	ID             string `json:"id"`
	ScopeStatement string `json:"scope_statement"`
}

// DocRef is a hashed reference to another document — the same id +
// content_sha256 shape evidence-manifest/v1 uses for an artifact or
// environment-profile reference.
type DocRef struct {
	ID            string `json:"id"`
	ContentSHA256 string `json:"content_sha256"`
}

// EvidenceClass names which layer produced an ObjectiveRow's resolved value.
type EvidenceClass string

// The two evidence classes docs/assessment-reporting.md's Invariant 2 names.
const (
	EvidenceMachine  EvidenceClass = "machine"
	EvidenceOperator EvidenceClass = "operator"
)

// ObjectiveRow is one control's resolved status.
type ObjectiveRow struct {
	ID              string        `json:"id"`
	EvidenceClass   EvidenceClass `json:"evidence_class"`
	EvidencePointer string        `json:"evidence_pointer,omitempty"`
	Determination   string        `json:"determination,omitempty"`
	Resolved        string        `json:"resolved"`
}

// L1Summary is the CMMC L1-specific rollup.
type L1Summary struct {
	MetCount            int  `json:"met_count"`
	NotMetCount         int  `json:"not_met_count"`
	Total               int  `json:"total"`
	AffirmationPossible bool `json:"affirmation_possible"`
}
