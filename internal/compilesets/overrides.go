// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Overrides names the human decisions DESIGN §9's Config-rule union defers
// to when it cannot resolve a parameter conflict on its own: "hard error
// with a conflict report demanding explicit resolution (an override file)."
//
// Unpublished (no schema/ entry, per CLAUDE.md rule 6): this is a small,
// operator-local file with no cross-institution provenance requirement,
// unlike an environment profile or a control artifact that travels between
// parties. Go-level validation only.
type Overrides struct {
	Entries []Override `json:"overrides"`
}

// Override resolves one rule parameter's conflict to a literal value —
// DESIGN §9's own wording for the remedy ("the value you intend"), not a
// choice between which artifact wins: an operator resolving a conflict
// between three or more artifacts would otherwise have to name one as
// authoritative for a value none of them may individually hold, and a
// literal value is what every conflict report already prints for the
// operator to copy.
type Override struct {
	Rule      string `json:"rule"`
	Parameter string `json:"parameter"`
	Value     string `json:"value"`
}

// LoadOverrides reads and validates an override file.
//
// Unknown fields are rejected, the same discipline every document this
// tool reads applies: an override file with a typo'd key silently resolves
// nothing, and the conflict it was meant to fix still hard-errors — better
// to refuse the file than to let an operator believe they had fixed it.
//
// # Duplicate keys are refused, on the same read path as every other document (AUDIT-4 H1)
//
// artifact.RejectDuplicateKeys runs before the decode, because
// DisallowUnknownFields does not fire on a key that is known twice —
// `"value": "14", "value": "6"` decodes to 6 with no complaint, and the
// operator reviewing the file reads the 14. AUDIT-2 H8 established this
// refusal on every document automat reads; this file is a document automat
// reads, and it is the one whose whole purpose is to state a single value a
// human decided on. Unpublished (no JSON Schema) does not make it exempt: it
// makes the Go read path the only place the refusal can live.
func LoadOverrides(path string) (*Overrides, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, same trust level as --environment-profile
	if err != nil {
		return nil, fmt.Errorf("read override file %s: %w", path, err)
	}
	if err := artifact.RejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("override file %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var o Overrides
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("parse override file %s: %w", path, err)
	}
	if err := o.validate(); err != nil {
		return nil, fmt.Errorf("override file %s: %w", path, err)
	}
	return &o, nil
}

func (o *Overrides) validate() error {
	seen := map[string]bool{}
	for i, e := range o.Entries {
		if e.Rule == "" {
			return fmt.Errorf("overrides[%d]: no rule was given", i)
		}
		if e.Parameter == "" {
			return fmt.Errorf("overrides[%d]: no parameter was given", i)
		}
		if e.Value == "" {
			return fmt.Errorf("overrides[%d]: no value was given — an override with no value would "+
				"resolve the conflict to nothing, which no Config rule accepts", i)
		}
		key := e.Rule + "\x00" + e.Parameter
		if seen[key] {
			return fmt.Errorf("overrides[%d]: %s parameter %s is overridden twice; automat will not "+
				"guess which entry is meant", i, safe(e.Rule), safe(e.Parameter))
		}
		seen[key] = true
	}
	return nil
}

// find returns the override for (rule, parameter), if any.
func (o *Overrides) find(rule, parameter string) (Override, bool) {
	if o == nil {
		return Override{}, false
	}
	for _, e := range o.Entries {
		if e.Rule == rule && e.Parameter == parameter {
			return e, true
		}
	}
	return Override{}, false
}

// apply resolves a conflict using an override, if one names (rule,
// parameter) — returning the override's value verbatim, at the order the
// conflicting parameters themselves declared, since an override states a
// VALUE, not a new order to resolve under.
//
// A caller passes this to resolveParameter as the fallback a genuine
// conflict tries before giving up; see combineConfigRules and
// addOneConfigRule.
func (o *Overrides) apply(rule, parameter string, order artifact.ParamOrder) (artifact.RuleParameter, bool) {
	ov, ok := o.find(rule, parameter)
	if !ok {
		return artifact.RuleParameter{}, false
	}
	return artifact.RuleParameter{Value: ov.Value, Order: order}, true
}
