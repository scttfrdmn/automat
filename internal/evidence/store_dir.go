// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/safeio"
)

// Dir is an evidence directory resolved once, through which manifests are read and
// written.
//
// # Why a type rather than two functions taking a path
//
// Load and Write each take a path, resolve its directory, and operate. That is two
// resolutions of one name, and `vend` performs both against the same manifest in the
// same command — read the existing chain, append, write it back. Nothing tied them
// together, so the directory the chain was read from and the directory it was written
// to were only conventionally the same place. Resolving once and keeping the
// descriptor is what makes them the same place by construction.
//
// # The split between base and rel is a trust boundary
//
// base is where automat was run or told to work: operator territory, resolved by
// name, because an operator naming a path through a symlinked parent is naming a real
// location and refusing that would refuse every temp directory on darwin.
//
// rel is `baseline.evidence.local_dir`, read out of an environment profile. That is a
// document automat did not write, and its components are distrusted exactly as every
// other field of one is. AUDIT-2 (H1) reproduced the consequence of not drawing the
// line: a profile carrying `local_dir: "out/evidence"`, a symlink named `out` in the
// working directory, and an evidence manifest that landed outside the working
// directory while the birth certificate printed the path inside it. automat reported
// one location and wrote to another, and the document it did that to is the one an
// auditor is shown.
//
// safeio.EnsureDirUnder is where the component-at-a-time descent lives.
type Dir struct {
	root  *os.Root
	shown string
}

// OpenDir resolves rel beneath base, creating what does not exist, and returns the
// directory manifests will be read and written through.
//
// The caller closes it. Nothing here reads or writes a manifest; a failure means the
// directory itself could not be established, which is worth distinguishing from a
// failure about a particular chain.
func OpenDir(base, rel string) (*Dir, error) {
	root, err := safeio.EnsureDirUnder(base, rel, manifestDirMode)
	if err != nil {
		return nil, fmt.Errorf("prepare the evidence directory: %w", err)
	}
	return &Dir{root: root, shown: filepath.Join(base, rel)}, nil
}

// Close releases the directory descriptor.
func (d *Dir) Close() error {
	if d == nil || d.root == nil {
		return nil
	}
	return d.root.Close()
}

// Path is the path to an account's manifest, for printing.
//
// Printing and opening are different operations here on purpose: this composes a
// string for a person, and every actual open goes through the descriptor. What must
// never recur is the case where the two disagree — see the type comment — so this
// renders the same base and rel that were resolved, and no name is joined a second
// time on the way to a syscall.
func (d *Dir) Path(accountID string) string {
	return filepath.Join(d.shown, accountID+".json")
}

// LoadOrNew reads the chain for an account, or starts one if there is no file yet.
//
// The shape `vend` needs, and the same reasoning as the package-level LoadOrNew: a
// first vend against an account has no manifest and a second has one, and both are
// ordinary. Every other failure — unreadable, a symlink, a broken chain — is an
// error, because "start a fresh chain" is the wrong recovery for all of them, and
// silently starting over on a manifest that failed to parse is how a tampered chain
// gets replaced by a clean one.
//
// # The identity arguments are not only for the new-file branch (AUDIT-2 M1)
//
// They used to be. accountID, id and organizationID were passed to NewManifest and
// otherwise discarded, so a file at 999988887777.json containing account
// 111122223333's valid, verified, correctly-linked chain was ADOPTED: the caller's
// record was appended to the other account's chain and written back over it. Neither
// the shape checks nor the chain checks notice, because nothing about that manifest is
// malformed — it is simply about a different account than the one asked for.
//
// So the loaded manifest is checked against what was asked for. This is the read-side
// half of validateHeaderAgainstRecords: that one binds a manifest's header to its own
// records, and this binds it to the account the CALLER named. Both exist because a
// correct-looking document filed in the wrong place reads to an auditor as evidence
// about an account it is not about.
func (d *Dir) LoadOrNew(accountID, id, organizationID, createdAt string, verifier Verifier) (*Manifest, error) {
	return d.LoadOrNewNamed(accountID, id, accountID, organizationID, createdAt, verifier)
}

// LoadOrNewNamed is LoadOrNew generalized over a filename key distinct from
// the account id being checked against the loaded manifest's content.
//
// LoadOrNew's own accountID parameter does double duty: it is both the
// filename key (accountID+".json") and the identity LoadOrNew's checkIsAbout
// call verifies the loaded manifest is actually about. Those coincide for
// every manifest until rotation (Q23, docs/open-questions.md): a rotated
// manifest's successor is filed as "<accountID>-2.json" while remaining a
// manifest ABOUT accountID, so a caller resolving which file currently
// receives an account's records needs to open by one name and check identity
// against another.
func (d *Dir) LoadOrNewNamed(key, id, accountID, organizationID, createdAt string, verifier Verifier) (*Manifest, error) {
	name := key + ".json"
	shown := d.Path(key)

	f, _, err := safeio.OpenChecked(d.root, name, shown)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return NewManifest(id, accountID, organizationID, createdAt), nil
	default:
		return nil, fmt.Errorf("read the evidence manifest: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", shown, err)
	}
	if int64(len(data)) > MaxManifestBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes, so it is not the manifest automat "+
			"expected — a chain of real operations does not reach that size", shown, MaxManifestBytes)
	}
	m, err := Decode(data, verifier)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", shown, err)
	}
	if err := m.checkIsAbout(accountID, organizationID, shown); err != nil {
		return nil, err
	}
	return m, nil
}

// checkIsAbout refuses a loaded manifest that is not about the account it was asked
// for. See LoadOrNew's comment for what this is defending against.
//
// The organization is compared only when both sides name one, and a manifest with no
// organization_id at all is not refused: the field is optional in the schema, a vend
// from the STANDALONE state has no organization to name, and refusing a manifest for a
// field it was never required to carry would make older manifests unreadable for a
// reason unrelated to whose they are.
func (m *Manifest) checkIsAbout(accountID, organizationID, shown string) error {
	if got := m.Meta.AccountID; got != "" && accountID != "" && got != accountID {
		return fmt.Errorf("%s is the evidence manifest for account %s, but this run is recording "+
			"operations against %s. automat will not append to another account's chain: the record "+
			"would be filed under an account it is not about, and the chain it joined would then say "+
			"that account was operated on when it was not. Move or rename the file, or check the "+
			"environment profile's baseline.evidence.local_dir",
			shown, safe(got), safe(accountID))
	}
	if got := m.Meta.OrganizationID; got != "" && organizationID != "" && got != organizationID {
		return fmt.Errorf("%s is the evidence manifest for an account in organization %s, but this run "+
			"is in %s. An account belongs to one organization at a time, so this is either a manifest "+
			"copied between organizations or a chain that outlived a migration; either way, appending "+
			"to it would produce a chain that spans two organizations without saying so",
			shown, safe(got), safe(organizationID))
	}
	return nil
}

// Exists reports whether a manifest file named key+".json" is already present
// in this directory, without reading or validating its content.
//
// For Path/LoadOrNew/Write, key is ordinarily the account id. Rotation (Q23)
// is the exception: a rotated manifest's successor is named
// "<accountID>-2.json", "<accountID>-3.json", and so on, and a caller
// choosing the next free suffix needs to ask "is this name taken" without
// paying for a full Decode of whatever is there — the file, if present, is
// someone else's chain and not this call's business to parse.
func (d *Dir) Exists(key string) (bool, error) {
	_, err := d.root.Lstat(key + ".json")
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("check for %s: %w", d.Path(key), err)
	}
}

// ListAccountIDs returns the account id every manifest file in this directory
// names, sorted — the id being whatever precedes ".json" in the filename, not
// a field read out of the manifest's own content.
//
// `automat list` needs to enumerate what is here before it can load anything,
// and the filename is what `Path`/`Write` already use as the account's key —
// reading it back is cheaper and cannot disagree with itself the way parsing
// every file's Meta.AccountID and hoping it matches the filename could.
// Entries that are not ordinary files ending in ".json" are skipped rather
// than reported: a stray directory or dotfile in an evidence tree is not an
// account's manifest, and this is an inventory, not a validator — `list`
// loads each entry through LoadOrNew/Load afterward, where a malformed file
// is a real failure to surface for that one account rather than a name to
// silently drop.
func (d *Dir) ListAccountIDs() ([]string, error) {
	entries, err := fs.ReadDir(d.root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", d.shown, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || id == "" {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// Write writes a manifest into this directory, with the same temp-file-first
// discipline as the package-level Write and through the same checked open.
func (d *Dir) Write(m *Manifest, accountID string) error {
	return d.WriteNamed(m, accountID)
}

// WriteNamed is Write generalized over a filename key distinct from the
// account id, for the same reason LoadOrNewNamed exists: a rotated manifest's
// successor (Q23, docs/open-questions.md) is filed as
// "<accountID>-2.json", not "<accountID>.json", while its Meta.AccountID is
// still the account it is about.
func (d *Dir) WriteNamed(m *Manifest, key string) error {
	base := key + ".json"
	shown := d.Path(key)
	if err := m.Validate(); err != nil {
		return fmt.Errorf("refusing to write %s: %w", shown, err)
	}
	data, err := m.MarshalIndented()
	if err != nil {
		return err
	}
	return writePair(d.root, base, shown, filepath.Dir(shown), data)
}
