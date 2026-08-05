// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package safeio holds the one filesystem rule this tool cannot afford to get
// wrong in three places independently: resolve a path once, then operate on the
// descriptor.
//
// A check on a *name* followed by an action on the same *name* is two operations
// on two potentially different objects, however narrow the window looks. automat
// hits that pattern at three points, each involving a secret:
//
//   - internal/bundle writes an onboarding bundle containing a live sts:ExternalId.
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
