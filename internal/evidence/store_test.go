// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// storeManifest is the two-record chain the round-trip cases share.
func storeManifest(t *testing.T, signer Signer) *Manifest {
	t.Helper()
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), signer)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), signer)
	return m
}

func TestWriteAndLoadRoundTrip(t *testing.T) {
	signer := testSigner(t)
	m := storeManifest(t, signer)
	path := filepath.Join(t.TempDir(), "evidence", "111122223333.json")

	if err := m.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	back, err := Load(path, signer.Verifier())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(back.Records) != len(m.Records) {
		t.Fatalf("loaded %d records, wrote %d", len(back.Records), len(m.Records))
	}
	for i := range m.Records {
		if back.Records[i].RecordSHA != m.Records[i].RecordSHA {
			t.Errorf("records[%d].record_sha256 changed across the write: %q then %q",
				i, m.Records[i].RecordSHA, back.Records[i].RecordSHA)
		}
	}
	// Byte-stable: writing what was loaded reproduces the file. This is what lets a
	// manifest live in a git repository without churning, and what lets two mirrors
	// of one chain be compared without a JSON parser (DESIGN §11).
	first, err := os.ReadFile(path) //nolint:gosec // test-local path
	if err != nil {
		t.Fatal(err)
	}
	again, err := back.MarshalIndented()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(again) {
		t.Errorf("re-marshalling a loaded manifest produced different bytes:\n%s\n---\n%s", first, again)
	}
	// The temp file is cleaned up on success; leaving it would mean every manifest
	// directory accumulates a second copy of the chain that nothing updates.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the evidence directory holds %v, want only the manifest", names)
	}
}

// TestWriteIsIdempotent. CLAUDE.md rule 4: re-running a mutating command must be
// safe, and for the manifest that means re-writing an unchanged chain changes
// nothing on disk.
func TestWriteIsIdempotent(t *testing.T) {
	m := storeManifest(t, nil)
	path := filepath.Join(t.TempDir(), "m.json")
	if err := m.Write(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path) //nolint:gosec // test-local path
	if err != nil {
		t.Fatal(err)
	}
	if werr := m.Write(path); werr != nil {
		t.Fatalf("the second Write failed: %v", werr)
	}
	second, err := os.ReadFile(path) //nolint:gosec // test-local path
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("writing the same manifest twice produced different bytes")
	}
}

// TestAWrittenManifestIsOwnerOnly. Not a secret, but it holds operator ARNs,
// account ids, and the OU structure of an institution's regulated-research estate,
// so the default is narrow and widening it is the operator's decision.
func TestAWrittenManifestIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence", "m.json")
	if err := storeManifest(t, nil).Write(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("manifest mode is %#o, want 0600", got)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("evidence directory mode is %#o, want 0700", got)
	}
}

// TestWriteTightensALoosenedManifest is why the mode is set with fchmod rather than
// trusted from O_CREATE, whose mode is masked by the umask and ignored entirely for
// a file that already exists.
func TestWriteTightensALoosenedManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := storeManifest(t, nil).Write(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("manifest mode is %#o after a rewrite, want 0600: O_CREATE's mode is ignored for "+
			"an existing file, which is why the mode is set on the descriptor", got)
	}
}

// TestWriteReplacesAShorterManifest: without the truncate, appending a record to a
// chain whose new form is shorter than the old would leave trailing bytes of the
// previous document — which Decode reports as trailing content, sending the reader
// after a second manifest that was never written.
func TestWriteReplacesAShorterManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	long := storeManifest(t, nil)
	if err := long.Write(path); err != nil {
		t.Fatal(err)
	}
	short := newTestManifest()
	mustAppend(t, short, vendRec(OpAccountCreate, ts0), nil)
	if err := short.Write(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, nil); err != nil {
		t.Errorf("a shorter manifest written over a longer one does not load, so the file holds "+
			"trailing bytes of the previous document:\n%v", err)
	}
}

// TestTheCompleteChainSurvivesAFailedWrite is the reason for the temp file.
//
// A truncated manifest is worse than a truncated bundle template: a short final
// record is indistinguishable from a truncated chain, which is exactly the signal
// the terminal record exists to preserve. So the whole new content lands at a
// sibling path first, and if the real write fails the operator is told where it is.
func TestTheCompleteChainSurvivesAFailedWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	// A directory where the manifest belongs: the temp write succeeds, the real one
	// cannot. Stands in for any failure in that window.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	err := storeManifest(t, nil).Write(path)
	if err == nil {
		t.Fatal("Write succeeded with a directory in the manifest's place")
	}
	tmp := filepath.Join(dir, ".automat-m.json.tmp")
	if !strings.Contains(err.Error(), tmp) {
		t.Errorf("the error must name the path holding the complete chain:\n%v", err)
	}
	data, rerr := os.ReadFile(tmp) //nolint:gosec // test-local path
	if rerr != nil {
		t.Fatalf("the complete chain was not left at %s: %v", tmp, rerr)
	}
	recovered, derr := Decode(data, nil)
	if derr != nil {
		t.Fatalf("the recoverable copy does not parse, which makes it no recovery at all: %v", derr)
	}
	if len(recovered.Records) != 2 {
		t.Errorf("the recoverable copy holds %d records, want 2", len(recovered.Records))
	}
}

// TestWriteRefusesAnInvalidManifest. Validated first and the write refused rather
// than attempted: a half-valid manifest on disk is a chain an operator will be told
// to investigate, and the investigation would find automat's own bug.
func TestWriteRefusesAnInvalidManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	m := storeManifest(t, nil)
	m.Records[1].Sequence = 9

	if err := m.Write(path); err == nil {
		t.Fatal("Write accepted a manifest with a renumbered record")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a refused Write created the file anyway")
	}
	// And nothing was left behind to be mistaken for the real thing.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a refused Write left %d entries in the directory", len(entries))
	}
}

// TestAnEmptyManifestIsNotWritten: a manifest exists to record operations, and one
// with none is a file with no subject. The case matters because `vend` builds the
// manifest before it does anything, so a run that fails at preflight must not leave
// an empty chain that reads as "nothing was attempted, successfully".
func TestAnEmptyManifestIsNotWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	err := newTestManifest().Write(path)
	if err == nil {
		t.Fatal("Write accepted a manifest with no records")
	}
	if !strings.Contains(err.Error(), "a file with no subject") {
		t.Errorf("the error must say why:\n%v", err)
	}
}

func TestLoadOrNewOnAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing-here.json")
	m, err := LoadOrNew(path, acct, acct, "o-abc1234567", ts0, nil)
	if err != nil {
		t.Fatalf("a missing manifest is the ordinary first-vend case, not an error: %v", err)
	}
	if len(m.Records) != 0 || m.Meta.ID != acct || m.Meta.CreatedAt != ts0 {
		t.Errorf("LoadOrNew returned %+v, want a fresh manifest for %s", m.Meta, acct)
	}
	// The second vend finds the file.
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	if werr := m.Write(path); werr != nil {
		t.Fatal(werr)
	}
	again, err := LoadOrNew(path, acct, acct, "o-abc1234567", ts1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Records) != 1 {
		t.Errorf("the second LoadOrNew returned %d records, want the 1 already written",
			len(again.Records))
	}
	if again.Meta.CreatedAt != ts0 {
		t.Errorf("created_at = %q, want the original %q: an existing manifest's header is not "+
			"restamped by a later run", again.Meta.CreatedAt, ts0)
	}
}

// TestLoadOrNewDoesNotStartOverOnAnUnreadableManifest is the one that matters.
//
// Silently starting a fresh chain when the existing one fails to parse is how a
// tampered chain gets replaced by a clean one — and the replacement would then be
// written back over the evidence. A missing file is ordinary; everything else is an
// error, because "start over" is the wrong recovery for all of it.
func TestLoadOrNewDoesNotStartOverOnAnUnreadableManifest(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		content string
	}{
		{"a truncated file", `{"schema_version":"1.0.0","manifest":{`},
		{"an empty file", ""},
		{"a file that is not JSON at all", "this used to be evidence\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "m.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrNew(path, acct, acct, "o-abc1234567", ts0, nil); err == nil {
				t.Errorf("LoadOrNew started a fresh chain over %s", tc.name)
			}
		})
	}

	// A manifest whose chain is broken is the sharpest form: it parses, so only the
	// chain check stands between the tamperer and a clean replacement.
	m := storeManifest(t, nil)
	m.Records[1].Artifact.ContentSHA256 = otherHash
	data, err := m.MarshalIndented()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tampered.json")
	if werr := os.WriteFile(path, data, 0o600); werr != nil {
		t.Fatal(werr)
	}
	_, err = LoadOrNew(path, acct, acct, "o-abc1234567", ts0, nil)
	if err == nil {
		t.Fatal("LoadOrNew started a fresh chain over an edited manifest, which is how a tampered " +
			"chain gets replaced by a clean one")
	}
	if !strings.Contains(err.Error(), "edited after it was written") {
		t.Errorf("the error must name the edit:\n%v", err)
	}
}

// TestDecodeRejectsAnUnknownField. In an evidence document an ignored field is worse
// than elsewhere: it is a claim the writer made and the reader silently dropped,
// which is the one thing a chain of custody must not do.
func TestDecodeRejectsAnUnknownField(t *testing.T) {
	m := storeManifest(t, nil)
	data, err := m.MarshalIndented()
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if uerr := json.Unmarshal(data, &generic); uerr != nil {
		t.Fatal(uerr)
	}
	recs, ok := generic["records"].([]any)
	if !ok {
		t.Fatal("records is not an array")
	}
	rec, ok := recs[0].(map[string]any)
	if !ok {
		t.Fatal("records[0] is not an object")
	}
	// The shape that matters: a claim a future version would carry, silently
	// dropped by this one. It is not covered by the record hash, so a reader would
	// see a verifying chain and a field nobody checked.
	rec["approved_by"] = "the compliance office"
	mutated, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decode(mutated, nil)
	if err == nil {
		t.Fatal("Decode silently dropped an unknown field in a record")
	}
	for _, want := range []string{"approved_by", "the reader dropped"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must name the field and say why it matters; %q missing from:\n%v",
				want, err)
		}
	}
}

func TestDecodeRejectsTrailingContent(t *testing.T) {
	m := storeManifest(t, nil)
	data, err := m.MarshalIndented()
	if err != nil {
		t.Fatal(err)
	}
	// Two documents in one file: a reader using a lenient parser sees the first, one
	// scanning for the last sees the second.
	doubled := append(append([]byte{}, data...), data...)

	_, err = Decode(doubled, nil)
	if err == nil {
		t.Fatal("Decode accepted two manifests in one file")
	}
	if !strings.Contains(err.Error(), "two readers see different chains") {
		t.Errorf("the error must say what a second document would achieve:\n%v", err)
	}
}

func TestDecodeReportsATypeErrorUsefully(t *testing.T) {
	_, err := Decode([]byte(`{"schema_version":"1.0.0","manifest":{"id":"x",`+
		`"created_at":"2026-08-05T00:00:00Z"},"records":"not an array"}`), nil)
	if err == nil {
		t.Fatal("Decode accepted a string where the record array belongs")
	}
	if !strings.Contains(err.Error(), "wrong type") {
		t.Errorf("the error must name the type problem:\n%v", err)
	}
}

// TestLoadRefusesASymlinkedManifest. A manifest is not a secret, but it must not be
// substitutable: it is the document an auditor is shown.
func TestLoadRefusesASymlinkedManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := storeManifest(t, nil).Write(real); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "shown-to-the-auditor.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	_, err := Load(link, nil)
	if err == nil {
		t.Fatal("Load followed a symlink at the manifest path")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("the error must name the cause:\n%v", err)
	}
}

// TestLoadRefusesAFIFOWithoutHanging: opening a pipe waits for the other end, so
// without O_NONBLOCK this hangs with no output at all — an operator running
// `automat list` would see it stop and learn nothing.
func TestLoadRefusesAFIFOWithoutHanging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs")
	}
	path := filepath.Join(t.TempDir(), "m.json")
	if err := mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Load(path, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was accepted as a manifest")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("the error does not name the cause: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Load blocked on a FIFO at the manifest path")
	}
}

// TestLoadRefusesAnOversizeManifest: the path can be operator-supplied, and an
// unbounded read of one is a way to exhaust memory. Over the bound is an error
// rather than a truncation, because a truncated manifest would fail the chain check
// and send the reader after tampering that is not there.
func TestLoadRefusesAnOversizeManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: a real MaxManifestBytes+1 of content would be 8MiB of test I/O.
	if terr := f.Truncate(MaxManifestBytes + 1); terr != nil {
		_ = f.Close()
		t.Fatal(terr)
	}
	if cerr := f.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	_, err = Load(path, nil)
	if err == nil {
		t.Fatal("Load accepted a file over MaxManifestBytes")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("the error must say the file is too large rather than reporting a parse failure:\n%v", err)
	}
}

// TestMarshalCanonicalIsParserFreeComparable. Two copies of one chain — the local
// one and the mirror in the vended account's bucket (DESIGN §11) — must be
// comparable without a JSON parser, which means the canonical form cannot depend on
// map iteration order or on how the file was indented.
func TestMarshalCanonicalIsParserFreeComparable(t *testing.T) {
	m := storeManifest(t, testSigner(t))
	first, err := m.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	// A round trip through the on-disk form must not change the canonical bytes.
	indented, err := m.MarshalIndented()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(indented, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := back.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("the canonical form changed across a write and a read:\n%s\n---\n%s", first, second)
	}
	if strings.Contains(string(first), "\n  ") {
		t.Error("the canonical form carries indentation, so it is the on-disk form and not a " +
			"canonicalization")
	}
	if !strings.HasSuffix(string(first), "\n") {
		t.Error("the canonical form has no trailing newline")
	}
	// Repeated calls agree — the guard against map iteration order leaking in.
	for i := 0; i < 8; i++ {
		again, err := m.MarshalCanonical()
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("MarshalCanonical is not deterministic across calls (differed on run %d)", i+1)
		}
	}
}

// TestTheOnDiskFormDoesNotEscapeHTML: an account name containing an ampersand is
// ordinary, and & in the file would make the manifest harder to read for no
// gain. It must also not change the hash, which goes through CanonicalRecordJSON
// rather than this.
func TestTheOnDiskFormDoesNotEscapeHTML(t *testing.T) {
	m := newTestManifest()
	rec := vendRec(OpAccountCreate, ts0)
	rec.Target.AccountName = "Physics & Astronomy <shared>"
	stored := mustAppend(t, m, rec, nil)

	data, err := m.MarshalIndented()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Physics & Astronomy <shared>") {
		t.Errorf("the on-disk form escaped HTML in an account name:\n%s", data)
	}
	back, err := Decode(data, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if back.Records[0].RecordSHA != stored.RecordSHA {
		t.Error("an account name with an ampersand changed the hash across a write and a read")
	}
}
