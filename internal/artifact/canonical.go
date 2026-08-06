// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// It deliberately does not touch Meta.ContentHash — ContentHash covers the
// content payload and not the metadata carrying it (HashCoveredFields), so
// canonicalizing then hashing is well defined.
func (a *Artifact) Canonicalize() {
	a.Meta.Sources.canonicalize()
	a.Controls.canonicalize()
	// Sorted and deduped, like every other set-valued member. Order in the source
	// file must not reach the hash: two catalogs listing the same exempt services
	// in different orders describe one policy and must hash as one.
	a.RegionDenyExemptServices = sortedUniqueKeepEmpty(a.RegionDenyExemptServices)
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
		if c.SCP.isEmpty() {
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

// isEmpty reports whether the SCP block carries nothing at all.
//
// One predicate rather than a condition repeated in canonicalize and validate:
// they must agree, because canonicalize drops an empty block so it cannot perturb
// the hash and validate rejects one. A field added to the type and to only one of
// those two lists would either be silently dropped or make an otherwise-empty
// block un-droppable.
func (s *SCP) isEmpty() bool {
	return len(s.Statements) == 0 && len(s.RegionAllowlist) == 0 &&
		len(s.ServiceAllowlist) == 0
}

func (s *SCPStatement) canonicalize() {
	s.Action = sortedUnique(s.Action)
	s.Resource = sortedUnique(s.Resource)
	s.ExemptPrincipals = s.ExemptPrincipals.Canonical()
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

// Canonical sorts the exemption list by principal and drops entries that are
// duplicates in both fields, the same way sortedUnique treats an action list.
//
// It deliberately keeps two entries that name the same principal with different
// reasons: that is a conflict a human must resolve, and silently picking one
// would let the artifact hash agree while the two files disagree about why a
// hole in a Deny exists. Validate rejects it — canonicalization normalizes, it
// does not adjudicate.
//
// Exported because the SCP packer intersects exemption lists and its output has
// to be in the same canonical form this hashes: two spellings of one exemption
// set must not produce two policies.
func (es ExemptPrincipals) Canonical() ExemptPrincipals {
	if len(es) == 0 {
		return nil
	}
	seen := make(map[ExemptPrincipal]bool, len(es))
	out := make(ExemptPrincipals, 0, len(es))
	for _, e := range es {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Principal != out[j].Principal {
			return out[i].Principal < out[j].Principal
		}
		return out[i].Reason < out[j].Reason
	})
	return out
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

// sortedUniqueKeepEmpty is sortedUnique for the one field where present-but-empty
// and absent are different claims.
//
// region_deny_exempt_services absent says the artifact states no AWS endpoint
// facts, which is the ordinary case. Present-but-empty would claim no service is
// globally addressed, which is false about AWS and which Validate rejects — so
// canonicalization must not quietly turn one into the other and hide the error.
func sortedUniqueKeepEmpty(in []string) []string {
	if in == nil {
		return nil
	}
	if out := sortedUnique(in); out != nil {
		return out
	}
	return []string{}
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

// CanonicalJSON returns the canonical JSON encoding of any value: object keys
// sorted, no insignificant whitespace, no HTML escaping, and numeric literals
// preserved exactly as written.
//
// Exported for internal/evidence, which hashes records with it. There is one
// canonicalization in automat on purpose: a record must hash identically when it
// is written and when it is read back off disk years later, and two
// implementations of "canonical" is how that stops being true. The doc comment on
// canonicalJSON explains why the round trip through interface{} is what makes the
// guarantee hold for a shape this package does not own.
func CanonicalJSON(v any) ([]byte, error) { return canonicalJSON(v) }

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

// contentPayload is the part of an artifact the content hash covers.
//
// An explicit struct rather than hashing *Artifact with metadata blanked, so that
// adding a field to Artifact is a decision about hash coverage rather than a
// default. HashCoveredFields and HashExcludedFields, asserted against reflection
// in the tests, are what make forgetting that decision a build failure instead of
// a silent gap.
type contentPayload struct {
	Controls Controls `json:"controls"`
	// RegionDenyExemptServices decides whether a rendered region Deny covers IAM,
	// so leaving it outside the hash would mean an edit that widens the Deny's
	// holes — adding `s3`, say — passes VerifyContentHash unremarked.
	//
	// omitempty collapses `[]` and absent to the same hash, and that is fine HERE
	// though it is not fine in Canonicalize. Present-but-empty is a different and
	// invalid claim — absent says the artifact states no AWS endpoint facts, `[]`
	// would say no service is globally addressed — but it is rejected by both the
	// JSON Schema's minItems and Validate, so no document carrying it can be
	// written or loaded. The place that must not launder one into the other is
	// canonicalization, which runs before Write validates; see
	// sortedUniqueKeepEmpty.
	RegionDenyExemptServices []string `json:"region_deny_exempt_services,omitempty"`
}

// HashCoveredFields names the Artifact fields ComputeContentHash covers, by Go
// field name. The test suite asserts this against contentPayload and Artifact.
var HashCoveredFields = []string{"Controls", "RegionDenyExemptServices"}

// HashExcludedFields names the Artifact fields the content hash deliberately
// does NOT cover, with the reason each is safe to exclude.
//
//   - SchemaVersion: a version bump that changed the meaning of the covered
//     fields would change their encoding too, and Validate rejects a major this
//     build does not understand before any hash is consulted.
//   - Meta: compiled_at changes on every run, and content_sha256 cannot cover
//     itself. Recompiling unchanged content must yield the same hash or every
//     tag and evidence record referencing it becomes meaningless.
//
// Meta.Sources is the uncomfortable member of that second group: provenance is
// semantic. It stays excluded because it is checked by its own per-source
// sha256 values, which are what a reviewer actually traces.
var HashExcludedFields = []string{"SchemaVersion", "Meta"}

// CanonicalContentJSON returns the canonical JSON encoding of the artifact's
// hashed content: controls[] plus the artifact-level global-service exemption
// list, if it has one.
//
// This is the exact byte sequence ContentHash covers. Exported because `verify`
// and the evidence chain need to recompute it independently of the surrounding
// artifact metadata — the whole point is that re-compiling the same content with
// a different timestamp yields the same content hash.
func (a *Artifact) CanonicalContentJSON() ([]byte, error) {
	dup := a.clone()
	dup.Controls.canonicalize()
	if dup.Controls == nil {
		dup.Controls = Controls{}
	}
	// Read the exemption list from a, not dup: clone round-trips through JSON and
	// the field carries omitempty, so an empty list would not survive the clone.
	// The clone exists to canonicalize controls[] without mutating the caller's
	// artifact, and nothing more.
	payload := contentPayload{
		Controls:                 dup.Controls,
		RegionDenyExemptServices: sortedUnique(a.RegionDenyExemptServices),
	}
	return canonicalJSON(payload)
}

// ComputeContentHash returns the SHA-256 of the canonicalized content payload.
//
// It excludes artifact metadata by design; see HashExcludedFields for which
// fields and why each is safe.
func (a *Artifact) ComputeContentHash() (string, error) {
	b, err := a.CanonicalContentJSON()
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

// RejectDuplicateKeys refuses a JSON document that names any object key twice.
//
// encoding/json takes the LAST occurrence of a duplicate key and reports nothing,
// which turns a hashed document into two documents: the one a person reads, and the
// one automat loaded. AUDIT-2 established the reach empirically rather than by
// argument — a second `"review_by"` appended to an environment profile vends
// successfully and prints 2099-12-31 on the birth certificate while the file on disk
// says 2027-06-30, and `review_by` is inside the content hash precisely so that
// extending a review date is a change no earlier attestation vouches for.
//
// # Why the existing checks do not cover this
//
//   - DisallowUnknownFields does not fire: the key IS known, twice.
//   - The JSON Schema does not either. `additionalProperties: false` constrains
//     which names may appear, not how often; RFC 8259 permits duplicates and leaves
//     the behavior to the implementation.
//   - VerifyContentHash catches it only where a hash is already recorded and the
//     duplicate falls inside the hashed payload. A duplicate in Meta does not, and
//     the hash is computed FROM the parse, so a document whose hash is set after the
//     duplicate was introduced is self-consistent and wrong.
//   - An attestation catches it, and only for a document that carries one.
//     Signatures are optional everywhere, so the ordinary unattested profile — the
//     usual case — has no backstop at all.
//
// Scanned with a token decoder rather than by unmarshalling into map[string]any,
// which would itself collapse the duplicates this is looking for. Nesting is tracked
// with an explicit stack of per-container frames: two sibling objects may of course
// use the same key, and only a repeat within ONE object is the defect.
//
// # Why the frame records whether its container is an object
//
// json.Decoder.Token does not say whether a string token is a key or a value, and
// alternation alone cannot recover it: an array of strings has no keys at all, so
// counting "every other string is a key" misreads every element of one. The first
// draft of this function did exactly that and refused a valid artifact, reporting
// `the key "scp" appears twice` — "scp" being an enforcement CLASS, a value, listed
// once per control. An over-strict check that rejects real documents is not a safe
// direction to fail in; it is a load path that stops working.
//
// So each frame records its container kind. Only an object frame holds a key set, and
// a string is a key only when the innermost open container is an object AND the frame
// is positioned for a key — which is true after '{' and after each value completes.
//
// The path in the error names the offending object, because "review_by appears twice"
// in a document with several objects that could hold one is not actionable on its own.
func RejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	// One frame per open container. pending is the key the next container will be
	// labelled with in the path.
	var stack []*keyFrame
	var pending string

	// valueDone advances the enclosing container past a completed value: an object
	// expects a key next, an array counts one more element.
	//
	// It also clears pending, which is what a key is held in only until the value it
	// labels begins. Left set, it labels the NEXT container instead: in
	// {"controls":[{"id":1},{"id":2}]} the "id" of the first element would still be
	// pending when the second element opens, so a duplicate inside that element was
	// reported at `controls.id` — a path that does not exist in the document.
	valueDone := func() {
		pending = ""
		if n := len(stack); n > 0 {
			if top := stack[n-1]; top.object {
				top.expectKey = true
			} else {
				top.elems++
			}
		}
	}

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// Malformed JSON is not this function's finding to report: the caller's
			// own decode produces a better message, with an offset and a type. Return
			// nil and let it speak.
			return nil //nolint:nilerr // syntax errors are the caller's to report
		}

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				f := &keyFrame{object: t == '{', label: pending}
				if f.object {
					f.keys = map[string]bool{}
					f.expectKey = true
				}
				if f.label == "" && len(stack) > 0 && !stack[len(stack)-1].object {
					// An element of an array has no key; name it by position.
					f.label = fmt.Sprintf("[%d]", stack[len(stack)-1].elems)
				}
				stack = append(stack, f)
				pending = ""
			case '}', ']':
				stack = stack[:len(stack)-1]
				// The container that just closed was a value in its parent.
				valueDone()
			}
		case string:
			top := len(stack) - 1
			if top >= 0 && stack[top].object && stack[top].expectKey {
				if stack[top].keys[t] {
					return fmt.Errorf("the key %q appears twice in %s.\n"+
						"JSON parsers take the last occurrence and report nothing, so the document "+
						"automat loaded is not the document you are reading: a hashed field can be "+
						"changed by APPENDING a second copy of it, leaving the original line visible "+
						"and inert. Delete whichever of the two is wrong", t, framePath(stack))
				}
				stack[top].keys[t] = true
				stack[top].expectKey = false
				pending = t
				continue
			}
			valueDone()
		default:
			// A number, bool, or null: always a value.
			valueDone()
		}
	}
}

// keyFrame is one open JSON container during a duplicate-key scan.
type keyFrame struct {
	// object distinguishes {} from []. An array frame never holds keys — see
	// RejectDuplicateKeys for why guessing from alternation is wrong.
	object bool
	// keys is the set already seen in this object; nil for an array frame.
	keys map[string]bool
	// expectKey is true when the next string token in this object is a key.
	expectKey bool
	// elems counts completed elements of an array frame, for the path label.
	elems int
	// label is the key (or [index]) this container hangs off its parent by.
	label string
}

// framePath renders the dotted path to the innermost open container.
func framePath(stack []*keyFrame) string {
	var b strings.Builder
	for _, f := range stack {
		switch {
		case f.label == "":
			continue
		case strings.HasPrefix(f.label, "["):
			b.WriteString(f.label)
		default:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(f.label)
		}
	}
	if b.Len() == 0 {
		return "the top-level object"
	}
	return b.String()
}
