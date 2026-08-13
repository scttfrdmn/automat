// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package safeio holds the one filesystem rule this tool cannot afford to get
// wrong in three places independently: resolve a path once, then operate on the
// descriptor.
//
// A check on a *name* followed by an action on the same *name* is two operations
// on two potentially different objects, however narrow the window looks. automat
// hits that pattern at three points, each handling something an attacker would want
// to substitute:
//
//   - internal/bundle writes the onboarding bundle — five files that are an IAM grant
//     a management account is about to review and apply. Not a secret: the
//     sts:ExternalId is supplied at deploy time by whoever applies the templates.
//     What is at stake is the *integrity* of a policy someone else will deploy, which
//     is why this one is in the list despite carrying nothing confidential.
//   - internal/login writes an SSO bearer token to ~/.aws/sso/cache.
//   - internal/config reads the ExternalId back at assume time.
//
// Those were three separate implementations of the same discipline, which is
// exactly how one of them ends up a version behind. The rules live here instead.
//
// # What os.Root does and does not do
//
// os.Root is the right primitive and it is narrower than it looks. Verified
// against go1.24 on darwin:
//
//   - It refuses a symlink that *escapes* the root ("path escapes from parent").
//   - It *follows* a symlink whose target is inside the root.
//   - It silently *ignores* syscall.O_NOFOLLOW in OpenFile's flags. Plain
//     os.OpenFile honors it and returns ELOOP; os.Root does not.
//
// So os.Root alone does not answer "am I opening the file I looked at". This
// package answers it by comparing the descriptor to the Lstat that preceded it
// with os.SameFile: if anything swapped the name in between, the identity differs
// and the operation is refused rather than completed against the wrong inode.
//
// # Why O_NONBLOCK
//
// Opening a FIFO for reading blocks until a writer arrives. A mode-0600 FIFO the
// operator owns passes every permission check and hangs automat forever, which
// turns "read the ExternalId" into a denial of service that looks like a network
// stall. O_NONBLOCK makes the open return so the regular-file check can reject it.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SecretFileMode is the only mode a file holding a secret may have.
const SecretFileMode fs.FileMode = 0o600

// SecretDirMode is the mode a directory holding secrets is kept at.
const SecretDirMode fs.FileMode = 0o700

// ReadSecret reads a file that holds a secret, refusing every shape that would
// let someone other than its owner choose the contents.
//
// limit bounds the read: a secret is short, and an unbounded read of a path an
// attacker may control is a way to exhaust memory. A file larger than limit is an
// error rather than a truncation, because a truncated secret is a value that fails
// authentication for a reason nobody would guess.
//
// The errors name the file and the one command that fixes it (CLAUDE.md rule 7).
// None of them echo the contents: the whole point of the file is that its value
// does not appear in terminals or CI logs.
func ReadSecret(path string, limit int64) ([]byte, error) {
	f, fi, err := OpenSecret(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// limit+1 so a file exactly at the limit is accepted and one byte over is
	// detected rather than silently cut.
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes (mode %s), so it is not the secret "+
			"automat expected — check that the path points at the value and not at a log or a keyring "+
			"database", path, limit, fi.Mode().Perm())
	}
	return data, nil
}

// ReadConfig reads a configuration file: the structural checks of ReadSecret
// without the ownership and mode requirements.
//
// The distinction is deliberate and it is not laziness about the mode. A config file
// is meant to be readable — an operator may well keep it group-readable so a
// colleague can see which org a context points at — so requiring 0600 would refuse
// a legitimate setup. What must still hold is that the path names an ordinary file
// nobody else can substitute: automat's config carries external_id_ref, and whoever
// chooses that reference chooses the ExternalId, which is the confused-deputy
// defense. A symlink or a FIFO at the config path is that substitution, and a
// world-writable containing directory means anyone can perform it whatever the
// file's own mode says.
//
// So: same refusals for a symlink, a non-regular file, a swapped inode, and an
// unsticky world-writable parent; no check on the file's own permission bits or
// owner.
func ReadConfig(path string, limit int64) ([]byte, error) {
	f, fi, err := openChecked(path, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes (mode %s), so it is not the "+
			"configuration automat expected — check that the path points at a config file",
			path, limit, fi.Mode().Perm())
	}
	return data, nil
}

// OpenSecret opens path and returns the descriptor together with the FileInfo the
// checks were made against. Callers that only want the bytes should use ReadSecret.
//
// Every check below is made against the descriptor or against an identity
// comparison with it, never against the path a second time.
func OpenSecret(path string) (*os.File, fs.FileInfo, error) {
	return openChecked(path, true)
}

// OpenChecked opens name for reading inside an ALREADY RESOLVED root, applying the
// same descriptor discipline openChecked applies to a path.
//
// The difference from ReadConfig is which resolution happened and when. ReadConfig
// takes a path and resolves its directory itself, which is right when the directory
// is the caller's only handle on the location. This one is for a caller that resolved
// the directory earlier — because it is going to read AND write through it, and the
// two must reach the same place by construction rather than by both being handed the
// same string. internal/evidence's Dir is that caller.
//
// A missing file is returned as fs.ErrNotExist unwrapped, so a caller can use
// errors.Is: for an evidence chain, "no manifest yet" is the first vend, not an error.
//
// shown is the path in error messages: root-relative names are what the syscalls take.
func OpenChecked(root *os.Root, name, shown string) (*os.File, fs.FileInfo, error) {
	if di, derr := root.Stat("."); derr == nil {
		if perm := di.Mode().Perm(); perm&0o022 != 0 && di.Mode()&fs.ModeSticky == 0 {
			return nil, nil, fmt.Errorf("the directory holding %s is mode %#o, writable beyond its "+
				"owner — anyone who can write it can replace the file, so its own mode is not a "+
				"protection. Run: chmod 700 %s", shown, perm, filepath.Dir(shown))
		}
	}

	li, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("inspect %s: %w", shown, err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s is a symbolic link (to %s), and automat will not read it "+
			"through one: whoever controls the link controls what is read. Replace it with the file "+
			"itself, or point the reference at the target directly",
			shown, LinkTarget(filepath.Dir(shown), name))
	}
	if !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file (mode %s) — automat reads from files, "+
			"not from devices, sockets, or pipes", shown, li.Mode())
	}

	f, err := root.OpenFile(name, os.O_RDONLY|OpenNonBlock, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", shown, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("inspect the open %s: %w", shown, err)
	}
	if err := checkOpen(shown, li, fi, false); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// openChecked is the shared body of OpenSecret and ReadConfig. secret selects the
// checks that only make sense for a file whose contents are a credential: its own
// permission bits and its owner. Everything else -- the writable-directory refusal,
// the symlink refusal, O_NONBLOCK, and the SameFile identity tie -- applies to both,
// because both answer the question "is this the file the operator named, and can
// anyone else substitute it".
func openChecked(path string, secret bool) (*os.File, fs.FileInfo, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return nil, nil, fmt.Errorf("%s does not name a file", path)
	}

	// Resolve the directory once. Every operation after this is relative to this
	// descriptor, so a component of dir being swapped afterwards changes nothing:
	// the root still refers to the directory that was resolved here.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("open the directory holding %s: %w", path, err)
	}
	defer func() { _ = root.Close() }()

	// A directory anyone may write is a directory in which anyone may replace this
	// file, so the file's own mode proves nothing. Sticky is the exception that
	// makes /tmp usable: it stops one user deleting or renaming another's entry.
	if di, derr := root.Stat("."); derr == nil {
		if perm := di.Mode().Perm(); perm&0o022 != 0 && di.Mode()&fs.ModeSticky == 0 {
			return nil, nil, fmt.Errorf("the directory holding %s is mode %#o, writable beyond its "+
				"owner — anyone who can write it can replace the file, so its own mode is not a "+
				"protection. Run: chmod 700 %s", path, perm, dir)
		}
	}

	// Lstat before opening, for two different reasons. It refuses a symlink, which
	// os.Root would otherwise follow when the target is inside the root and which
	// O_NOFOLLOW does not prevent through os.Root. And it produces the identity
	// this file must still have when the descriptor is checked below.
	li, err := root.Lstat(base)
	if errors.Is(err, fs.ErrNotExist) {
		if !secret {
			// Returned unwrapped so a caller can use errors.Is: config.Load treats a
			// missing file as "no configuration", which is not an error.
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("no file at %s — create it containing only the value, "+
			"readable by you alone: touch %s && chmod 600 %s", path, path, path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s is a symbolic link (to %s), and automat will not read %s "+
			"through one: whoever controls the link controls the value. Replace it with the "+
			"file itself, or point the reference at the target directly",
			path, LinkTarget(dir, base), subject(secret))
	}
	if !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file (mode %s) — %s comes from a "+
			"file, not from a device, socket, or pipe", path, li.Mode(), subject(secret))
	}

	// O_NONBLOCK so that a FIFO swapped in after the check above cannot hang this
	// process; the regular-file check on the descriptor then rejects it.
	f, err := root.OpenFile(base, os.O_RDONLY|OpenNonBlock, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("inspect the open %s: %w", path, err)
	}

	if err := checkOpen(path, li, fi, secret); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// checkOpen holds the checks that must be made against the descriptor rather than
// the name. Split out so a test can state each one independently.
func checkOpen(path string, li, fi fs.FileInfo, secret bool) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (mode %s) — %s comes from a file, not "+
			"from a device, socket, or pipe", path, fi.Mode(), subject(secret))
	}
	// The identity check. If the name refers to a different object now than it did
	// a moment ago, someone is choosing which file automat reads.
	if !os.SameFile(li, fi) {
		return fmt.Errorf("%s changed while automat was opening it, so the file it checked is not "+
			"the file it opened — something else is writing that path. Nothing was read; investigate "+
			"before retrying", path)
	}
	// Refusing a loose mode rather than warning: a warning about a value whose only
	// property is being unguessable is advice nobody acts on, and the fix is one
	// command. Note this reads the *descriptor's* mode, so a chmod racing the open
	// cannot present a tight mode to the check and a loose one to the read.
	// A config file is meant to be readable; only a secret's own mode is checked.
	if !secret {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s is mode %#o, readable beyond its owner — run: chmod 600 %s",
			path, perm, path)
	}
	if uid, ok := OwnerUID(fi); ok {
		// Compared as int64, which holds every uint32 and every int uid exactly, so
		// neither side is narrowed. Converting the other direction (int -> uint32)
		// would be a truncation, and a truncation here fails *open*: a uid whose low
		// 32 bits happen to match the caller's would be accepted as the owner.
		if me := os.Getuid(); me >= 0 && int64(uid) != int64(me) {
			return fmt.Errorf("%s is owned by uid %d, not by you (uid %d) — automat will not take a "+
				"secret from a file another account controls, because whoever owns it chooses the "+
				"value. Run: chown %d %s", path, uid, me, me, path)
		}
	}
	return nil
}

// CreateChecked opens name inside root for writing, applying on the write side the
// same discipline openChecked applies on the read side, and returns the descriptor
// every subsequent operation must use.
//
// shown is the path to name in error messages: root-relative names are what the
// syscalls take, and a full path is what an operator can act on.
//
// The returned file is positioned at offset zero and NOT truncated. Truncation is
// the caller's, because a caller that writes shorter content than the file already
// holds must truncate and one that does not must not, and getting that wrong is a
// silently corrupt file rather than a refusal. Callers close it, including alongside
// an error: a non-nil file may be returned with a non-nil error, because the checks
// that matter most are the ones made after the open.
//
// # Why this is not just root.OpenFile
//
// The read path in this package exists because a check on a name followed by an
// action on the same name is two operations on two potentially different objects.
// Writing has that problem and one more: a read through a substituted path leaks,
// and a write through one DESTROYS. Three shapes each pass every mode check —
//
//   - a symlink whose target is inside the root, which os.Root follows (see the
//     package comment; O_NOFOLLOW does not stop it) and through which O_CREATE
//     silently creates or clobbers the target;
//   - a hardlink, which is a regular file by every check Lstat can make, and writing
//     through which truncates whatever else shares the inode;
//   - a FIFO, on which an open for writing blocks until a reader appears — so
//     automat hangs with no output instead of refusing.
//
// AUDIT-2 found all three reachable at the evidence manifest path, where the file
// being written is the document an auditor is shown. They were unreachable at the
// bundle and login paths only because those had each grown the checks inline. This
// function is where they live now, which is the same reason the read side is here.
func CreateChecked(root *os.Root, name, shown string, mode fs.FileMode) (*os.File, error) {
	// O_EXCL first, so that "did it exist" and "create it" are one atomic operation
	// rather than a test followed by a create. Success means there was nothing there
	// to substitute, which is both the common case and the one with nothing to check.
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err == nil {
		return f, chmodChecked(f, shown, mode)
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create %s: %w", shown, err)
	}

	// It exists. Lstat through the root before opening, because opening is the thing
	// that must not happen if this is a symlink.
	li, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", shown, err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link (to %s), and automat will not write through "+
			"one: whoever controls the link chooses where the content lands, and a write lands on "+
			"the target rather than on the path you named. Remove it, or name the target directly",
			shown, LinkTarget(filepath.Dir(shown), name))
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s exists and is not a regular file (mode %s) — automat writes to "+
			"files, not to devices, sockets, or pipes; remove it or choose another path",
			shown, li.Mode())
	}

	// No O_CREATE: it exists, and re-asking for creation here would reintroduce the
	// clobber-through-a-link the Lstat above just refused. OpenNonBlock covers the
	// FIFO the Lstat cannot — one swapped in after the check — which would otherwise
	// block this open forever.
	f, err = root.OpenFile(name, os.O_WRONLY|OpenNonBlock, mode)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", shown, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return f, fmt.Errorf("inspect the open %s: %w", shown, err)
	}
	if !fi.Mode().IsRegular() {
		return f, fmt.Errorf("%s is not a regular file (mode %s) — automat writes to files, not to "+
			"devices, sockets, or pipes", shown, fi.Mode())
	}
	// The identity tie. Without it the Lstat and the open are two independent
	// resolutions, and whoever can write this directory decides which object the
	// second one reaches: the Lstat passes on a regular file they then replace.
	if !os.SameFile(li, fi) {
		return f, fmt.Errorf("%s changed while automat was opening it, so the file it inspected is "+
			"not the file it opened — something else is writing that path. Nothing was written; "+
			"investigate before retrying", shown)
	}
	if n, ok := LinkCount(fi); ok && n > 1 {
		return f, fmt.Errorf("%s has %d hard links — writing it would overwrite whatever else "+
			"shares that file, which automat was never pointed at. Remove %s or choose another path",
			shown, n, shown)
	}
	return f, chmodChecked(f, shown, mode)
}

// chmodChecked fixes the mode on the descriptor rather than trusting O_CREATE, which
// is masked by the umask and ignored entirely for a file that already exists.
//
// Before any content is written, which is what makes a write to an inode automat's
// user does not own fail closed: fchmod returns EPERM for a non-owner.
func chmodChecked(f *os.File, shown string, mode fs.FileMode) error {
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("set permissions on %s to %#o: %w", shown, mode.Perm(), err)
	}
	return nil
}

// EnsureDir resolves dir and returns a root scoped to it, creating it if needed
// and refusing to operate through a symlink standing where the directory belongs.
//
// The final component is created through a descriptor on its parent, so the
// classic create-then-open window — where the directory is made and something is
// planted at the name before it is opened — is not present: the Mkdir either wins
// or reports that the name is taken, and the taken case is inspected rather than
// assumed to be the directory that was wanted.
func EnsureDir(dir string, mode fs.FileMode) (*os.Root, error) {
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	if base == "." || base == string(filepath.Separator) {
		// The directory is a filesystem root or the working directory; there is
		// nothing to create and no parent to resolve it through.
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", dir, err)
		}
		return root, nil
	}

	// The parents above the final component are created by name. That is a
	// deliberate limit: automat cannot verify a path it was asked to create, and
	// an operator who names ~/work/bundles is asking for the directories in it.
	// What matters is that the *last* component, the one files are written into,
	// is resolved once and used as a descriptor from then on.
	if grandparent := filepath.Dir(parent); grandparent != parent {
		if err := os.MkdirAll(parent, mode); err != nil {
			return nil, fmt.Errorf("create %s: %w", parent, err)
		}
	}
	proot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", parent, err)
	}
	defer func() { _ = proot.Close() }()

	err = proot.Mkdir(base, mode)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrExist):
		// Something is already there. Find out what, through the parent's
		// descriptor, before writing anything into it.
		fi, lerr := proot.Lstat(base)
		if lerr != nil {
			return nil, fmt.Errorf("inspect the existing %s: %w", dir, lerr)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symbolic link (to %s), and automat will not write "+
				"through one: the files it writes hold a secret, and whoever controls the link "+
				"chooses where that secret lands. Remove it, or name the target directly",
				dir, LinkTarget(parent, base))
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("%s exists and is not a directory (mode %s)", dir, fi.Mode())
		}
	default:
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}

	root, err := proot.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	return root, nil
}

// EnsureDirUnder resolves base by name and then creates rel beneath it ONE
// COMPONENT AT A TIME through descriptors, refusing a symlink at any component of
// rel.
//
// The split between the two arguments is the whole point, and it is a trust
// boundary rather than a convenience. base is operator territory — a working
// directory, or a path from a CLI flag — and is resolved by name, because automat
// cannot verify a location it was told to use and because an operator naming a path
// through a symlinked parent is naming a real place. rel is DOCUMENT territory: the
// environment profile's baseline.evidence.local_dir, whose components automat is
// obliged to distrust exactly as it distrusts every other field of a signed
// document it did not write.
//
// # Why EnsureDir is not enough for this
//
// EnsureDir creates everything above its final component with os.MkdirAll, which
// resolves by name, and checks only the last one. Its doc comment says so and a test
// asserts it, because on darwin /tmp is itself a symlink and refusing every symlinked
// parent would refuse every temp directory. That limit is correct for a flag-derived
// path and wrong for a document-derived one: AUDIT-2 (H1) reproduced a profile
// carrying `local_dir: "out/evidence"` against a working directory containing a
// symlink named `out`, and the evidence manifest landed outside the working
// directory while the birth certificate printed the path inside it. automat reported
// one location and wrote to another, which for the document an auditor is shown is
// the worst available outcome.
//
// Confinement alone does not close it either. os.Root refuses an ESCAPING symlink,
// so the root that comes back is confined — to wherever the link pointed. The escape
// happens while the root is being built, not while it is being used, which is why
// this descends component by component instead of resolving the joined path once.
func EnsureDirUnder(base, rel string, mode fs.FileMode) (*os.Root, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", base, err)
	}

	rel = filepath.Clean(rel)
	if rel == "." {
		return root, nil
	}
	if filepath.IsAbs(rel) {
		_ = root.Close()
		return nil, fmt.Errorf("%s must be a relative path, and %q is absolute: it is read from a "+
			"document, and a document does not get to choose a location outside the directory automat "+
			"was pointed at", relSubject(rel), rel)
	}

	shown := base
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		shown = filepath.Join(shown, part)
		next, derr := descend(root, part, shown, mode)
		_ = root.Close()
		if derr != nil {
			return nil, derr
		}
		root = next
	}
	return root, nil
}

// OpenDirUnder is EnsureDirUnder's read-only sibling: it resolves rel beneath
// base ONE COMPONENT AT A TIME through descriptors, refusing a symlink at any
// component exactly as EnsureDirUnder does, but never creates anything. A
// missing component is reported as fs.ErrNotExist, unwrapped, so a caller
// can use errors.Is the same way OpenChecked's own missing-file case allows —
// "the directory does not exist yet" is not an error for a read-only checker
// that has no business creating it.
//
// This exists because EnsureDirUnder's own Mkdir-then-inspect shape is itself
// a mutation: the very thing a read-only caller (internal/verify's
// procedural-attestation check, checking a stub directory it must never
// create) cannot do. See EnsureDirUnder's own doc comment for the base/rel
// trust-boundary reasoning this reuses verbatim — base is operator territory,
// resolved by name; rel is document territory (here,
// baseline.attestations.local_dir), whose components this function distrusts
// exactly as EnsureDirUnder does, one component at a time, for the identical
// AUDIT-2 H1 reason.
func OpenDirUnder(base, rel string) (*os.Root, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", base, err)
	}

	rel = filepath.Clean(rel)
	if rel == "." {
		return root, nil
	}
	if filepath.IsAbs(rel) {
		_ = root.Close()
		return nil, fmt.Errorf("%s must be a relative path, and %q is absolute: it is read from a "+
			"document, and a document does not get to choose a location outside the directory automat "+
			"was pointed at", relSubject(rel), rel)
	}

	shown := base
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		shown = filepath.Join(shown, part)
		next, derr := descendReadOnly(root, part, shown)
		_ = root.Close()
		if derr != nil {
			return nil, derr
		}
		root = next
	}
	return root, nil
}

// descendReadOnly verifies one component exists, is not a symlink, and is a
// directory, then returns a root scoped to it — descend's read-only sibling:
// no Mkdir, ever.
func descendReadOnly(parent *os.Root, name, shown string) (*os.Root, error) {
	fi, err := parent.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", shown, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link (to %s), and automat will not read through one "+
			"on a path read from a document: whoever controls the link chooses what is read. Remove "+
			"it, or name the target directly",
			shown, LinkTarget(filepath.Dir(shown), name))
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s exists and is not a directory (mode %s)", shown, fi.Mode())
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", shown, err)
	}
	return root, nil
}

// descend creates or verifies one component and returns a root scoped to it.
//
// The Mkdir through the parent's descriptor is what makes this safe to repeat: it
// either wins, or reports that the name is taken, and the taken case is inspected
// rather than assumed to be the directory that was wanted. There is no window
// between a test and a create because there is no test.
func descend(parent *os.Root, name, shown string, mode fs.FileMode) (*os.Root, error) {
	err := parent.Mkdir(name, mode)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrExist):
		fi, lerr := parent.Lstat(name)
		if lerr != nil {
			return nil, fmt.Errorf("inspect the existing %s: %w", shown, lerr)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symbolic link (to %s), and automat will not create or "+
				"write through one on a path read from a document: whoever controls the link chooses "+
				"where the files land, and automat would report the path you named while writing "+
				"somewhere else. Remove it, or name the target directly",
				shown, LinkTarget(filepath.Dir(shown), name))
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("%s exists and is not a directory (mode %s)", shown, fi.Mode())
		}
	default:
		return nil, fmt.Errorf("create %s: %w", shown, err)
	}

	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", shown, err)
	}
	return root, nil
}

// relSubject names what a rejected relative path was, for one error message. Kept
// separate so the message reads as a statement about the field rather than about a
// variable.
func relSubject(string) string { return "a directory read from a document" }

// LinkTarget renders the target of a symlink for an error message, already quoted.
//
// Root.Readlink is Go 1.25 and the module floor is Go 1.24 (CLAUDE.md), so this
// reads the link by name via os.Readlink. That is a second resolution of a name
// already resolved through the root, which everywhere else in this package would be
// the bug. It is acceptable here and only here because of what the result is used
// for: this runs after the operation has already been refused, and the string goes
// into an error message. It opens nothing, reads no content, and grants nothing, so
// a swap between the two resolutions changes only which path is named in a message
// the operator is being told to go investigate anyway.
//
// The failure is reported the same way whether or not the target can be read, so
// nothing here can turn a refusal into a success.
func LinkTarget(dir, base string) string {
	target, err := os.Readlink(filepath.Join(dir, base))
	if err != nil {
		return quoteTarget("")
	}
	return quoteTarget(target)
}

// quoteTarget renders a symlink target for an error message. A link target is
// attacker-chosen in exactly the case this message is printed, so it goes through
// %q: no control byte, no escape sequence, and no newline can forge a second line
// of automat's output.
func quoteTarget(target string) string {
	if target == "" {
		return "an unreadable target"
	}
	const max = 120
	if len(target) > max {
		return fmt.Sprintf("%q (truncated)", target[:max])
	}
	return fmt.Sprintf("%q", target)
}

// subject names what is being read, so one set of refusals can explain itself in
// either context without a caller passing message text around.
func subject(secret bool) string {
	if secret {
		return "a secret"
	}
	return "configuration"
}
