// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestDecodeRoundTripsAProfileWithoutChangingItsHash is the round trip every evidence
// record depends on: what automat writes is what automat reads back, and it hashes the
// same both times.
func TestDecodeRoundTripsAProfileWithoutChangingItsHash(t *testing.T) {
	p := sampleProfile(t)
	want, err := p.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	data, err := p.MarshalIndented()
	if err != nil {
		t.Fatalf("MarshalIndented: %v", err)
	}

	got, err := Decode(data, LoadOptions{})
	if err != nil {
		t.Fatalf("Decode rejected what MarshalIndented produced:\n%v\n\ndocument:\n%s", err, data)
	}
	gotHash, err := got.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if gotHash != want {
		t.Errorf("the hash changed across a round trip: %s -> %s. Every evidence record naming this "+
			"profile would be unfalsifiable.", want, gotHash)
	}

	// And the bytes are stable too, which is what makes a committed profile reviewable
	// in a diff rather than churning on every write.
	again, err := got.MarshalIndented()
	if err != nil {
		t.Fatalf("MarshalIndented: %v", err)
	}
	if string(again) != string(data) {
		t.Errorf("re-marshalling produced different bytes:\n%s\n\nvs\n\n%s", data, again)
	}
}

// TestDecodeRefusesADocumentItWouldOtherwisePartlyUnderstand covers the parse-level
// refusals, all of which exist because the alternative is acting on half a document.
func TestDecodeRefusesADocumentItWouldOtherwisePartlyUnderstand(t *testing.T) {
	valid := func(t *testing.T) []byte {
		t.Helper()
		data, err := sampleProfile(t).MarshalIndented()
		if err != nil {
			t.Fatalf("MarshalIndented: %v", err)
		}
		return data
	}

	cases := []struct {
		name string
		want string
		data func(*testing.T) []byte
	}{
		{
			// The typo case: `permited` would silently mean no boundary at all.
			name: "an unknown field",
			want: "does not allow unknown fields",
			data: func(t *testing.T) []byte {
				return []byte(strings.Replace(string(valid(t)), `"permitted"`, `"permited"`, 1))
			},
		},
		{
			name: "malformed JSON",
			want: "malformed JSON at byte offset",
			data: func(t *testing.T) []byte {
				return []byte(strings.Replace(string(valid(t)), `"review_by":`, `"review_by" :: `, 1))
			},
		},
		{
			// The likeliest way a profile arrives broken — an interrupted copy, a
			// partial download, a file cut off by a full disk. encoding/json reports
			// io.ErrUnexpectedEOF with no offset and no hint, which reads as an automat
			// bug rather than as a file to re-fetch.
			name: "a truncated document",
			want: "the file is truncated",
			data: func(t *testing.T) []byte {
				d := valid(t)
				return d[:len(d)/2]
			},
		},
		{
			name: "a field of the wrong type",
			want: "has the wrong type",
			data: func(t *testing.T) []byte {
				var doc map[string]any
				if err := json.Unmarshal(valid(t), &doc); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				doc["control_sets"] = "cmmc-l1" // a string where a list belongs
				return mustMarshal(t, doc)
			},
		},
		{
			// A file with two documents in it is a mistake, not a profile, and picking
			// the first would act on a document the writer may not have meant.
			name: "two documents in one file",
			want: "trailing content",
			data: func(t *testing.T) []byte {
				d := valid(t)
				return append(append([]byte{}, d...), d...)
			},
		},
		{
			name: "an empty file",
			want: "EOF",
			data: func(_ *testing.T) []byte { return nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.data(t), LoadOptions{})
			if err == nil {
				t.Fatalf("Decode accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal for %s does not mention %q, so an operator cannot tell what to "+
					"fix:\n%v", tc.name, tc.want, err)
			}
		})
	}
}

// TestDecodeValidatesBeforeCanonicalizing pins the ordering in load.go.
//
// Canonicalization normalizes the sets whose present-but-empty form is the deny-all
// Validate exists to refuse. keepEmpty preserves that distinction deliberately, but
// ordering the two so the refusal CANNOT depend on it is cheaper than depending on it —
// and the assertion here is that the refusal names the malformed field rather than
// arriving later as some downstream confusion about an intersection.
func TestDecodeValidatesBeforeCanonicalizing(t *testing.T) {
	p := sampleProfile(t)
	raw := mustMarshal(t, p)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc["permitted"] = map[string]any{"regions": []any{}}

	_, err := Decode(mustMarshal(t, doc), LoadOptions{SkipAttestationSubjects: true})
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("want a *ValidationError, got %T: %v", err, err)
	}
	var found bool
	for _, prob := range ve.Problems {
		if prob.Path == "permitted.regions" && strings.Contains(prob.Message, "present but empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("no problem named permitted.regions as present-but-empty; the refusal must name the "+
			"malformed field rather than surface later as a disagreement between two documents:\n%v",
			ve)
	}
}

// TestDecodeChecksAttestationSubjectsUnlessAskedNotTo, and the option exists for exactly
// one caller.
//
// An operator who has just edited a profile holds a document whose attestations are,
// correctly, over the previous content. Refusing to load it would mean the only way to
// re-attest is to delete the old attestations first, blind — so the editing path skips
// the check and every other path does not.
func TestDecodeChecksAttestationSubjectsUnlessAskedNotTo(t *testing.T) {
	p := sampleProfile(t)
	p.ReviewBy = "2099-01-01" // a hashed field, so the attestations are now stale
	data := mustMarshal(t, p)

	if _, err := Decode(data, LoadOptions{}); err == nil {
		t.Error("Decode accepted a document whose attestations are over its previous content")
	}
	if _, err := Decode(data, LoadOptions{SkipAttestationSubjects: true}); err != nil {
		t.Errorf("SkipAttestationSubjects must load it — otherwise the only way to re-attest is to "+
			"delete the old attestations blind:\n%v", err)
	}
}

// TestDecodeRefusesASecondCopyOfAHashedField is the AUDIT-2 duplicate-key finding,
// asserted on the document type the harm was demonstrated against.
//
// The probe: append a second `"review_by"` to an environment profile and vend. It
// succeeds, and the birth certificate prints 2099-12-31 while the file on disk still
// reads 2027-06-30 on the line a reviewer's eye lands on. encoding/json takes the last
// occurrence and says nothing; DisallowUnknownFields does not fire because the key is
// known, twice; and `additionalProperties: false` in the schema constrains which names
// may appear, not how often.
//
// review_by is the sharpest instance because it is inside the content hash for exactly
// this reason — deferring a re-reading is a change no earlier attestation vouches for —
// but the check is unconditional, because the attestation that would catch it is
// optional and the unattested profile is the ordinary case. The subtests below assert
// that both the attested and the unattested document are refused.
func TestDecodeRefusesASecondCopyOfAHashedField(t *testing.T) {
	p := sampleProfile(t)
	data, err := p.MarshalIndented()
	if err != nil {
		t.Fatalf("MarshalIndented: %v", err)
	}
	if !strings.Contains(string(data), `"review_by": "`) {
		t.Fatalf("test setup: no review_by to duplicate in:\n%s", data)
	}
	// Appended AFTER the original, which is the direction that wins: the visible line
	// stays, and the value automat acts on is the one below it.
	doubled := []byte(strings.Replace(string(data),
		`"review_by": "`+p.ReviewBy+`",`,
		`"review_by": "`+p.ReviewBy+`",`+"\n  "+`"review_by": "2099-12-31",`, 1))
	if string(doubled) == string(data) {
		t.Fatal("test setup: the substitution did not fire")
	}

	for _, opts := range []struct {
		name string
		opts LoadOptions
	}{
		// The attested case: VerifyAttestationSubjects would also catch this one, since
		// the effective review date changed inside the hash. Asserted anyway, so the
		// refusal is not silently downgraded to that later, weaker check.
		{"attestations checked", LoadOptions{}},
		// The case with no backstop whatsoever. Signatures are optional, and a profile
		// that carries none has nothing else that notices.
		{"attestations skipped", LoadOptions{SkipAttestationSubjects: true}},
		// And validation off too, since SkipValidate is documented as skipping
		// validation rather than parsing.
		{"validation and attestations skipped", LoadOptions{SkipValidate: true, SkipAttestationSubjects: true}},
	} {
		t.Run(opts.name, func(t *testing.T) {
			got, err := Decode(doubled, opts.opts)
			if err == nil {
				t.Fatalf("Decode accepted a profile with two review_by keys and read it as %q; the "+
					"file says %q on the line a reviewer reads", got.ReviewBy, p.ReviewBy)
			}
			if !strings.Contains(err.Error(), "appears twice") {
				t.Errorf("the refusal does not name the duplicate, so an operator is told the wrong "+
					"thing to fix:\n%v", err)
			}
		})
	}

	// The unmodified profile still loads. A duplicate-key scanner that rejects valid
	// documents is not a stricter load path, it is a broken one.
	if _, err := Decode(data, LoadOptions{}); err != nil {
		t.Errorf("the scan refused an unmodified profile:\n%v", err)
	}
}

// TestSkipValidateIsForConstructingInvalidDocumentsDeliberately. It exists for tests, and
// the assertion is that it does not also skip the parse-level refusals: a malformed
// document is still malformed.
func TestSkipValidateIsForConstructingInvalidDocumentsDeliberately(t *testing.T) {
	p := sampleProfile(t)
	p.ControlSets = nil // Validate refuses this
	data := mustMarshal(t, p)

	if _, err := Decode(data, LoadOptions{SkipAttestationSubjects: true}); err == nil {
		t.Fatal("test setup: the document must be invalid for this to mean anything")
	}
	if _, err := Decode(data, LoadOptions{SkipValidate: true, SkipAttestationSubjects: true}); err != nil {
		t.Errorf("SkipValidate must parse an invalid document:\n%v", err)
	}
	// Still parsed, though.
	if _, err := Decode([]byte(`{"schema_version":`), LoadOptions{SkipValidate: true}); err == nil {
		t.Error("SkipValidate accepted malformed JSON; it skips validation, not parsing")
	}
}

// TestLoadAndWriteRoundTripThroughDisk, including that Write creates the directory and
// leaves the file readable by whoever reviews it.
func TestLoadAndWriteRoundTripThroughDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "research-cui.json")

	p := sampleProfile(t)
	if err := p.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Load(path, LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wantHash, err := p.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	gotHash, err := got.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if gotHash != wantHash {
		t.Errorf("hash changed through disk: %s -> %s", wantHash, gotHash)
	}

	// An environment profile is a reviewed, committed document containing no secrets
	// (DESIGN §13). 0600 would break the ordinary case of a profile read by CI running
	// as a different account.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %v, want 0644: this document is meant to be read by the office that "+
			"approved it, and by design holds no secrets", perm)
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("Write did not create the parent directory: %v", err)
	}
}

// TestWriteRefusesAnInvalidDocumentAndLeavesNothingBehind.
//
// Both halves matter. Validating first means automat never commits a posture nobody
// chose; leaving no temp file behind means a failed write does not litter the directory
// an operator is about to commit.
func TestWriteRefusesAnInvalidDocumentAndLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.json")

	p := sampleProfile(t)
	p.Placement.TargetOU = "not-an-ou"
	if err := p.Write(path); err == nil {
		t.Fatal("Write accepted an invalid profile")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Write created the file anyway (stat: %v)", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Write left %d file(s) behind: %v", len(entries), entries)
	}
}

// TestWriteDoesNotCheckAttestationSubjects.
//
// Writing is HOW a document becomes the thing its attestations are stale against — an
// operator changing a control set has, correctly, an unattested edit. Refusing to write
// it would make the tool unusable for the ordinary act of editing, and the check that
// would fail is the same one the next Load performs.
func TestWriteDoesNotCheckAttestationSubjects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edited.json")
	p := sampleProfile(t)
	p.ControlSets = append(p.ControlSets, "800-171r2") // now unattested

	if err := p.Write(path); err != nil {
		t.Fatalf("Write refused a document with stale attestations. Writing is how a document "+
			"becomes stale against them, and the check belongs to the next Load:\n%v", err)
	}
	if _, err := Load(path, LoadOptions{}); err == nil {
		t.Error("Load accepted the written document; the staleness has to surface somewhere, and " +
			"reading is where")
	}
}

// TestWriteIsAtomicAgainstAnExistingFile: a failed write must not damage the profile
// already on disk. A half-written document that still parses would be worse than a
// missing one, because it would describe a posture nobody chose.
func TestWriteIsAtomicAgainstAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	good := sampleProfile(t)
	if err := good.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // test-local temp path
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	bad := sampleProfile(t)
	bad.Meta.ID = "Not An Id"
	if werr := bad.Write(path); werr == nil {
		t.Fatal("Write accepted an invalid profile")
	}

	after, err := os.ReadFile(path) //nolint:gosec // test-local temp path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(after) != string(before) {
		t.Error("a failed Write modified the profile already on disk")
	}
}

// TestLoadFSReadsAnEmbeddedProfile, which is how the shipped examples and the bundle
// templates will carry one.
func TestLoadFSReadsAnEmbeddedProfile(t *testing.T) {
	data, err := sampleProfile(t).MarshalIndented()
	if err != nil {
		t.Fatalf("MarshalIndented: %v", err)
	}
	fsys := fstest.MapFS{"examples/research-cui.json": &fstest.MapFile{Data: data}}

	if _, lerr := LoadFS(fsys, "examples/research-cui.json", LoadOptions{}); lerr != nil {
		t.Errorf("LoadFS: %v", lerr)
	}
	_, err = LoadFS(fsys, "examples/missing.json", LoadOptions{})
	if err == nil {
		t.Error("LoadFS accepted a path that does not exist")
	} else if !strings.Contains(err.Error(), "examples/missing.json") {
		t.Errorf("the error does not name the path:\n%v", err)
	}
}

// TestLoadNamesThePathInEveryFailure. An operator running `vend` against one of several
// profiles needs to know which file was refused, and the validator's own subject is the
// profile ID — which is exactly the field that may be missing.
func TestLoadNamesThePathInEveryFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": "1.0.0"}`), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write: %v", err)
	}

	_, err := Load(path, LoadOptions{})
	if err == nil {
		t.Fatal("Load accepted a profile with almost no fields")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file, and the validator's own subject is the profile "+
			"id — the field most likely to be missing:\n%v", err)
	}

	_, err = Load(filepath.Join(dir, "absent.json"), LoadOptions{})
	if err == nil {
		t.Error("Load accepted a file that does not exist")
	} else if !strings.Contains(err.Error(), "read environment profile") {
		t.Errorf("a missing file and an invalid one must be distinguishable:\n%v", err)
	}
}

// TestValidationProblemsAreReachableThroughErrorsAs is what makes a *ValidationError a
// value rather than a string (CLAUDE.md rule 7). A caller rendering a table of problems
// needs the paths, not a formatted paragraph.
func TestValidationProblemsAreReachableThroughErrorsAs(t *testing.T) {
	p := sampleProfile(t)
	p.Meta.ID = ""
	p.ReviewBy = ""
	p.Placement.TargetOU = ""

	err := p.Validate()
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("want a *ValidationError, got %T", err)
	}
	if len(ve.Problems) < 3 {
		t.Errorf("reported %d problems, want at least 3; an operator whose profile will not load "+
			"wants the whole list, not one line per run", len(ve.Problems))
	}
	for _, prob := range ve.Problems {
		if prob.Path == "" {
			t.Errorf("a problem has no path: %+v", prob)
		}
		if prob.Message == "" {
			t.Errorf("a problem has no message: %+v", prob)
		}
		if !errors.Is(err, prob) {
			t.Errorf("problem %q is not reachable through errors.Is; Unwrap must expose them",
				prob.Path)
		}
	}
	if !strings.Contains(ve.Error(), "3 problems") && !strings.Contains(ve.Error(), "problems") {
		t.Errorf("the summary does not say how many problems there are:\n%v", ve)
	}
}

// TestAnUntrustedValueCannotForgeALineOfTheProblemReport.
//
// An environment profile is attacker-controlled input in the threat model — an operator
// may have received one from a central IT office or forked an example — and this
// validator's output is a multi-line bulleted list. A value containing a newline could
// forge additional lines of that list, and an ANSI escape could hide or recolor real
// ones, so a reviewer reads a clean report while the document is anything but. Same
// defect and same fix as AUDIT-0's M1.
func TestAnUntrustedValueCannotForgeALineOfTheProblemReport(t *testing.T) {
	p := sampleProfile(t)
	p.Meta.ID = "bad\n  - placement.target_ou: fine — no problems here"

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted an id containing a newline")
	}
	rendered := err.Error()
	if strings.Contains(rendered, "\n  - placement.target_ou: fine") {
		t.Errorf("the profile id forged a line of the problem report:\n%s", rendered)
	}
	if !strings.Contains(rendered, `\n`) {
		t.Errorf("the newline was not escaped, so it is unclear the value is data rather than "+
			"structure:\n%s", rendered)
	}

	t.Run("and a long value is truncated rather than flooding the report", func(t *testing.T) {
		q := sampleProfile(t)
		q.Meta.ID = strings.Repeat("z", 4096)
		verr := q.Validate()
		if verr == nil {
			t.Fatal("Validate accepted a 4096-byte id")
		}
		if !strings.Contains(verr.Error(), "truncated from 4096 bytes") {
			t.Errorf("a long value was not truncated; a report nobody can read is a report nobody "+
				"reads:\n%v", verr)
		}
	})

	t.Run("the subject line is escaped too", func(t *testing.T) {
		// The subject is built from the id, which is the value most likely to be hostile
		// AND the one that appears before any problem — so an escape there recolors the
		// whole report.
		q := sampleProfile(t)
		q.Meta.ID = "x\x1b[31m"
		verr := q.Validate()
		if verr == nil {
			t.Fatal("Validate accepted an id containing an escape byte")
		}
		if strings.Contains(verr.Error(), "\x1b") {
			t.Errorf("an escape byte reached the rendered report:\n%q", verr.Error())
		}
	})
}
