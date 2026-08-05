// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Canonicalize puts the artifact into canonical form in place.
//
// Canonical form is what makes the content hash meaningful: two artifacts with
// the same controls must hash identically no matter what order their members
// arrived in. It sorts every set-valued member and normalizes empty collections
// to nil so that `[]` and absent hash the same.
//
// It deliberately does not touch Meta.ContentHash — ContentHash covers
// controls[] only, so canonicalizing then hashing is well defined.
func (a *Artifact) Canonicalize() {
	a.Meta.Sources.canonicalize()
	a.Controls.canonicalize()
}

func (s Sources) canonicalize() {
	sort.SliceStable(s, func(i, j int) bool {
		ki, vi, _ := s[i].kindKey()
		kj, vj, _ := s[j].kindKey()
		if ki != kj {
			return ki < kj
		}
		if vi != vj {
			return vi < vj
		}
		return s[i].SHA256 < s[j].SHA256
	})
}

func (cs Controls) canonicalize() {
	for i := range cs {
		cs[i].canonicalize()
	}
	// Controls sort by ID. IDs are unique within an artifact (Validate
	// enforces it), so this is a total order and the sort is stable in effect.
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
}

func (c *Control) canonicalize() {
	c.Enforcement = canonEnforcement(c.Enforcement)
	if len(c.Crosswalk) == 0 {
		c.Crosswalk = nil
	}

	if c.SCP != nil {
		c.SCP.canonicalize()
		// An SCP with nothing in it carries no meaning; drop it so it cannot
		// perturb the hash.
		if len(c.SCP.Statements) == 0 && len(c.SCP.RegionAllowlist) == 0 && len(c.SCP.ServiceAllowlist) == 0 {
			c.SCP = nil
		}
	}

	if len(c.ConfigRules) == 0 {
		c.ConfigRules = nil
	} else {
		for i := range c.ConfigRules {
			c.ConfigRules[i].canonicalize()
		}
		sort.SliceStable(c.ConfigRules, func(i, j int) bool {
			if c.ConfigRules[i].Identifier != c.ConfigRules[j].Identifier {
				return c.ConfigRules[i].Identifier < c.ConfigRules[j].Identifier
			}
			return c.ConfigRules[i].Name < c.ConfigRules[j].Name
		})
	}
}

// canonEnforcement dedupes and orders enforcement classes by the fixed order in
// AllEnforcementClasses, not alphabetically: the fixed order reads
// preventive-before-detective-before-procedural, which is the order humans
// reason about them in. Unknown values sort last and are preserved so that
// Validate, not Canonicalize, is what rejects them.
func canonEnforcement(in []EnforcementClass) []EnforcementClass {
	if len(in) == 0 {
		return nil
	}
	rank := make(map[EnforcementClass]int, len(AllEnforcementClasses))
	for i, c := range AllEnforcementClasses {
		rank[c] = i
	}
	seen := make(map[EnforcementClass]bool, len(in))
	out := make([]EnforcementClass, 0, len(in))
	for _, e := range in {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := rank[out[i]]
		rj, okj := rank[out[j]]
		switch {
		case oki && okj:
			return ri < rj
		case oki:
			return true
		case okj:
			return false
		default:
			return out[i] < out[j]
		}
	})
	return out
}

func (s *SCP) canonicalize() {
	for i := range s.Statements {
		s.Statements[i].canonicalize()
	}
	sort.SliceStable(s.Statements, func(i, j int) bool { return s.Statements[i].Sid < s.Statements[j].Sid })
	s.RegionAllowlist = sortedUnique(s.RegionAllowlist)
	s.ServiceAllowlist = sortedUnique(s.ServiceAllowlist)
}

func (s *SCPStatement) canonicalize() {
	s.Action = sortedUnique(s.Action)
	s.Resource = sortedUnique(s.Resource)
	if len(s.Condition) == 0 {
		s.Condition = nil
		return
	}
	for op, keys := range s.Condition {
		if len(keys) == 0 {
			delete(s.Condition, op)
			continue
		}
		for k, vals := range keys {
			keys[k] = sortedUnique(vals)
		}
	}
	if len(s.Condition) == 0 {
		s.Condition = nil
	}
}

func (r *ConfigRule) canonicalize() {
	r.ResourceTypes = sortedUnique(r.ResourceTypes)
	if len(r.Parameters) == 0 {
		r.Parameters = nil
		return
	}
	for name, param := range r.Parameters {
		param.canonicalize()
		r.Parameters[name] = param
	}
}

// canonicalize normalizes a set-valued parameter so that two spellings of the
// same set hash identically: members are trimmed, deduped, sorted, and rejoined
// on the separator. A scalar parameter's value is opaque and left alone.
//
// An explicit separator equal to the default is dropped, again so that the two
// spellings of "comma-separated" cannot produce two hashes.
func (p *RuleParameter) canonicalize() {
	if p.SetSeparator == DefaultSetSeparator {
		p.SetSeparator = ""
	}
	if !p.Order.IsSet() {
		return
	}
	p.Value = strings.Join(p.Members(), p.Separator())
}

// sortedUnique returns the input sorted with duplicates removed, or nil if the
// result would be empty. Returning nil for empty is what makes `[]` and absent
// hash identically.
func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// canonicalJSON marshals v as canonical JSON: object keys sorted, no
// insignificant whitespace, and no HTML escaping.
//
// Go's encoding/json already emits struct fields in declaration order and map
// keys in sorted order, which is deterministic — but it is deterministic for
// *our* types only. Round-tripping through interface{} makes the guarantee hold
// for any input shape, which matters because this same function hashes evidence
// records loaded from disk.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := marshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // preserve numeric literals exactly; never round through float64
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonicalize: re-decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonicalize: marshal: %w", err)
	}
	// Encode appends a newline.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			ks, err := marshalNoEscape(k)
			if err != nil {
				return err
			}
			buf.Write(ks)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		b, err := marshalNoEscape(v)
		if err != nil {
			return err
		}
		buf.Write(b)
		return nil
	}
}

// CanonicalControlsJSON returns the canonical JSON encoding of controls[] alone.
//
// This is the exact byte sequence ContentHash covers. Exported because `verify`
// and the evidence chain need to recompute it independently of the surrounding
// artifact metadata — the whole point is that re-compiling the same controls
// with a different timestamp yields the same content hash.
func (a *Artifact) CanonicalControlsJSON() ([]byte, error) {
	dup := a.clone()
	dup.Controls.canonicalize()
	if dup.Controls == nil {
		dup.Controls = Controls{}
	}
	return canonicalJSON(dup.Controls)
}

// ComputeContentHash returns the SHA-256 of the canonicalized controls[].
//
// It excludes artifact metadata by design: compiled_at changes on every run,
// and an artifact whose controls are unchanged must keep the same content hash
// or the tags and evidence records that reference it become meaningless.
func (a *Artifact) ComputeContentHash() (string, error) {
	b, err := a.CanonicalControlsJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SetContentHash canonicalizes the artifact and stores its computed content
// hash in Meta.ContentHash.
func (a *Artifact) SetContentHash() error {
	a.Canonicalize()
	h, err := a.ComputeContentHash()
	if err != nil {
		return err
	}
	a.Meta.ContentHash = h
	return nil
}

// VerifyContentHash recomputes the content hash and reports a mismatch as an
// error naming both values.
func (a *Artifact) VerifyContentHash() error {
	got, err := a.ComputeContentHash()
	if err != nil {
		return err
	}
	if a.Meta.ContentHash != got {
		return fmt.Errorf(
			"artifact %q content hash mismatch: document declares %s but its controls hash to %s; "+
				"the controls were edited without recompiling (run `make catalogs`) or the file is corrupt",
			a.Meta.ID, a.Meta.ContentHash, got)
	}
	return nil
}

// MarshalCanonical renders the whole artifact as canonical JSON with a trailing
// newline, suitable for writing to catalogs/ and for golden-file comparison.
func (a *Artifact) MarshalCanonical() ([]byte, error) {
	a.Canonicalize()
	b, err := canonicalJSON(a)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// MarshalIndented renders the artifact as stable, human-reviewable JSON with a
// trailing newline.
//
// Vendored catalogs use this form: a catalog is reviewed by humans in pull
// requests, so readability matters, and struct field order is deterministic.
// Hashing always goes through the canonical form, never this one.
func (a *Artifact) MarshalIndented() ([]byte, error) {
	a.Canonicalize()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		return nil, fmt.Errorf("marshal artifact %q: %w", a.Meta.ID, err)
	}
	return buf.Bytes(), nil
}

func (a *Artifact) clone() *Artifact {
	// Round-trip through JSON: a hand-written deep copy would silently miss
	// fields added to the types later, and this path is not hot.
	raw, err := marshalNoEscape(a)
	if err != nil {
		return a
	}
	var dup Artifact
	if err := json.Unmarshal(raw, &dup); err != nil {
		return a
	}
	return &dup
}
