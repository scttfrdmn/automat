// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/safeio"
)

// MaxManifestBytes bounds a manifest read.
//
// Eight megabytes is far more than a chain of real operations reaches — a record
// is roughly a kilobyte, so this is thousands of vends against one account — and
// the bound exists because a manifest path can be operator-supplied and an
// unbounded read of one is a way to exhaust memory. A file over the bound is an
// error rather than a truncation: a truncated manifest would fail the chain check
// and send the reader after tampering that is not there.
const MaxManifestBytes = 8 << 20

// RotateThresholdRecords is the record count at which a caller writing
// repeatedly to the same manifest — `verify` on a cron, or a heavily-resumed
// `vend` — should rotate to a fresh one via Manifest.Rotate (Q23,
// docs/open-questions.md).
//
// 2,000, well under the ~8,971-record ceiling MaxManifestBytes implies at
// roughly 935 bytes per record: rotation is meant to happen long before a
// manifest is at risk of refusing a write, not as a last-resort recovery from
// one. Triggered automatically by the caller, but visibly logged rather than
// silent — this project's stated preference for explicit, disclosed behavior
// over implicit magic (ROADMAP.md's Q23 entry).
const RotateThresholdRecords = 2000

// Decode parses a manifest from raw JSON and verifies its chain.
//
// Unknown fields are rejected. The schema declares additionalProperties false, and
// in an evidence document an ignored field is worse than elsewhere: it is a claim
// the writer made and the reader silently dropped, which is the one thing a chain
// of custody must not do.
//
// The chain is verified on load rather than on demand, because every caller wants
// it and the one that forgets is the one reading a tampered manifest. Signatures
// are checked when a verifier is supplied.
func Decode(data []byte, verifier Verifier) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, decodeError(err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	if err := m.VerifyChain(verifier); err != nil {
		return nil, err
	}
	return &m, nil
}

func ensureEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing content after the JSON document; a file holds " +
				"exactly one manifest, and a second document in it is either a mistake or an attempt " +
				"to have two readers see different chains")
		}
		return fmt.Errorf("unexpected trailing content after the JSON document: %w", err)
	}
	return nil
}

func decodeError(err error) error {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return fmt.Errorf("field %q has the wrong type: expected %s, got JSON %s (at byte offset %d)",
			ute.Field, ute.Type, ute.Value, ute.Offset)
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("malformed JSON at byte offset %d: %w", se.Offset, err)
	}
	if msg := err.Error(); strings.Contains(msg, "unknown field") {
		return fmt.Errorf("%w — the evidence manifest schema does not allow unknown fields, and an "+
			"ignored field in an evidence record is a claim the writer made and the reader dropped; "+
			"check for a typo, or bump the schema version if this is a new field", err)
	}
	return err
}

// Load reads and verifies a manifest from a file.
//
// Read through safeio.ReadConfig, not os.ReadFile. A manifest is not a secret —
// it is meant to be readable, and an operator may well keep it group-readable so
// a colleague can see what was vended — but what must still hold is that the path
// names an ordinary file nobody else can substitute. A symlink or a FIFO at the
// manifest path is that substitution, and a world-writable containing directory
// means anyone can perform it whatever the file's own mode says. That matters here
// because a manifest is what an auditor is shown.
func Load(path string, verifier Verifier) (*Manifest, error) {
	data, err := safeio.ReadConfig(path, MaxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read the evidence manifest: %w", err)
	}
	m, err := Decode(data, verifier)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// LoadOrNew reads a manifest, or returns a fresh one if the file does not exist.
//
// The shape `vend` needs: the first vend against an account has no manifest and
// the second has one, and both cases are ordinary. A missing file is not an error
// here; anything else about the file — unreadable, a symlink, a broken chain — is,
// because "start a fresh chain" would be the wrong recovery for every one of them.
// Silently starting over on a manifest that failed to parse is how a tampered
// chain gets replaced by a clean one.
func LoadOrNew(path, id, accountID, organizationID, createdAt string, verifier Verifier) (*Manifest, error) {
	m, err := Load(path, verifier)
	switch {
	case err == nil:
		return m, nil
	case errors.Is(err, fs.ErrNotExist):
		return NewManifest(id, accountID, organizationID, createdAt), nil
	default:
		return nil, err
	}
}

// MarshalIndented renders the manifest as stable, human-reviewable JSON with a
// trailing newline.
//
// This is the on-disk form. Indented rather than canonical, because a manifest is
// read by humans and diffed in a repository, and because — unlike the control
// artifact, whose whole file is hashed — nothing hashes a manifest as a whole.
// What is hashed is each record's canonical form, which this file's layout cannot
// affect. Hashing always goes through CanonicalRecordJSON, never through this.
func (m *Manifest) MarshalIndented() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("marshal evidence manifest %s: %w", safe(m.Meta.ID), err)
	}
	return buf.Bytes(), nil
}

// MarshalCanonical renders the whole manifest in canonical form with a trailing
// newline.
//
// Not the on-disk form. Here for the golden test and for a caller mirroring a
// manifest somewhere that compares bytes — two copies of the same chain, one
// local and one in the vended account's bucket (DESIGN §11), must be comparable
// without a JSON parser.
func (m *Manifest) MarshalCanonical() ([]byte, error) {
	b, err := artifact.CanonicalJSON(m)
	if err != nil {
		return nil, fmt.Errorf("canonicalize evidence manifest %s: %w", safe(m.Meta.ID), err)
	}
	return append(b, '\n'), nil
}

// Write writes the manifest to path, after validating it.
//
// Validated first, and the write refused rather than attempted: a half-valid
// manifest on disk is a chain an operator will be told to investigate, and the
// investigation would find automat's own bug.
//
// # Why not a rename
//
// A temp-file-and-rename would make the replacement atomic, and `os.Root.Rename`
// — the only form of it that cannot be redirected by a symlink swapped in at the
// directory's name — is Go 1.25, while the module floor is 1.24 (CLAUDE.md, and
// internal/bundle's writeThrough records the same constraint). Renaming by name
// instead would resolve the directory a second time, which is the pattern
// internal/safeio exists to refuse, and the thing being redirected here is the
// document an auditor is shown.
//
// So the real file is written through the resolved directory's descriptor. Because
// a truncated manifest is genuinely worse than a truncated bundle template — a
// short final record is indistinguishable from a truncated chain, which is exactly
// the signal the terminal record exists to preserve — the complete new content is
// written and flushed to a sibling temp file FIRST, and removed only once the real
// write has succeeded and been flushed. A crash in the window therefore leaves the
// whole new chain recoverable at a named path rather than lost, and Load's chain
// check is what tells the operator to go looking. When the floor reaches 1.25 this
// becomes a rename and the temp file stops being a fallback and becomes the
// mechanism.
//
// # Mode
//
// 0600. A manifest holds no secret, but it does hold operator ARNs, account ids,
// and the OU structure of an institution's regulated-research estate — so the
// default is the narrow one and widening it is the operator's decision. The mode
// is set on the descriptor with fchmod rather than trusted from O_CREATE, which is
// masked by the umask and ignored entirely for a file that already exists; and it
// is set before the write, which is what makes a write to an inode automat's user
// does not own fail closed, since fchmod returns EPERM for a non-owner.
func (m *Manifest) Write(path string) error {
	if err := m.Validate(); err != nil {
		return fmt.Errorf("refusing to write %s: %w", path, err)
	}
	data, err := m.MarshalIndented()
	if err != nil {
		return err
	}

	dir, base := filepath.Dir(path), filepath.Base(path)
	root, err := safeio.EnsureDir(dir, manifestDirMode)
	if err != nil {
		return fmt.Errorf("prepare the evidence directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	return writePair(root, base, path, dir, data)
}

// writePair performs the temp-file-first write of one manifest through an already
// resolved directory.
//
// Shared by Write and by Dir.Write so the ordering, the failure message, and the
// cleanup exist once. dir is used only to render the temp file's path in messages;
// every syscall goes through root.
func writePair(root *os.Root, base, shown, dir string, data []byte) error {
	tmp := ".automat-" + base + ".tmp"
	if err := writeThrough(root, tmp, filepath.Join(dir, tmp), data); err != nil {
		return err
	}
	if err := writeThrough(root, base, shown, data); err != nil {
		// The temp file is left in place deliberately: it holds the complete new
		// chain, and the named file may now be short.
		return fmt.Errorf("%w — the complete manifest was written to %s first and is still there; "+
			"move it into place once the cause is fixed", err, filepath.Join(dir, tmp))
	}
	if err := root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the temporary copy %s (the manifest itself was written): %w",
			filepath.Join(dir, tmp), err)
	}
	return nil
}

// writeThrough writes data to name inside root, creating or truncating it, with
// the mode fixed on the descriptor before any content is written.
//
// shown is the path to name in error messages: root-relative names are what the
// syscalls take and full paths are what an operator can act on.
//
// # The open is safeio's, and it was not always (AUDIT-2 H2)
//
// This function used to open the file itself, with a bare
// root.OpenFile(name, O_WRONLY|O_CREATE). os.Root confined the write, and
// confinement is not the whole property: within the directory, a symlink, a
// hardlink, or a FIFO planted at either name was written through, truncated
// through, or hung on. All three were reproduced against a real manifest —
// including a hardlink landing manifest bytes on a file entirely outside the root,
// which no confinement can prevent because a hardlink is not a path.
//
// The manifest's *real* name looked defended, because Write's caller reads through
// safeio.ReadConfig first and a planted non-manifest fails to parse. That is a JSON
// parser standing in for a filesystem check, and the sibling temp name — derived,
// predictable from the account id, and written FIRST — had no such accident
// covering it. The checks belong to the writer, so the writer now asks for them.
func writeThrough(root *os.Root, name, shown string, data []byte) error {
	f, err := safeio.CreateChecked(root, name, shown, manifestFileMode)
	if f != nil {
		defer func() { _ = f.Close() }()
	}
	if err != nil {
		return err
	}

	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("write %s: %w", shown, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", shown, err)
	}
	// Flushed rather than left to the page cache. Without it a crash can leave a
	// manifest that exists, is named correctly, and is empty — which reads as a
	// chain that was erased.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush %s: %w", shown, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", shown, err)
	}
	return nil
}

const (
	// manifestFileMode: see Write. Narrow by default, widened by the operator.
	manifestFileMode fs.FileMode = 0o600
	manifestDirMode  fs.FileMode = 0o700
)
