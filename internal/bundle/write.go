// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Writing the bundle to disk.
//
// # Why every write goes through os.Root
//
// AUDIT-0's A1 accepted three `G304` sites on the grounds that no path came from
// anywhere but a CLI flag, and recorded that the acceptance expires here: "this
// becomes a real finding the moment a path is derived from a profile, a bundle, or
// an API response, which is Phase 1's `setup --request` output directory". The
// human review made that condition binding.
//
// The bundle's five filenames are constants in this file, so a traversal through
// one of them is not the threat. The threat is the directory: automat is asked to
// write five files, one of which carries an `sts:ExternalId`, into a path the
// operator named, and a component of that path — or an entry inside it — can be a
// symlink, including one planted between the moment the directory is created and
// the moment the files are written. `os.Root` closes exactly that: the root is held
// as an open directory handle, so every subsequent operation resolves against the
// directory automat created rather than against whatever the name means later, and
// a symlink leading out of it fails with "path escapes from parent" instead of
// writing the ExternalId somewhere else.
//
// os.Root's own WriteFile is Go 1.25; the module floor is 1.24, so writes go
// through Root.OpenFile.

// The five files, in the order they are reported. README first because it is the
// one a reviewer opens.
const (
	FileREADME     = "README.md"
	FileOU         = "ou.md"
	FilePolicy     = "delegation-policy.json"
	FileRoleCFN    = "vendor-role.cfn.yaml"
	FileRoleTF     = "vendor-role.tf"
	dirMode        = fs.FileMode(0o700)
	fileMode       = fs.FileMode(0o600)
	renderersCount = 5
)

// renderer pairs a filename with the function that produces it. Keeping the set
// in one list is what lets TestEveryBundleFileIsRendered assert the bundle has
// five files and no renderer is unreachable.
var renderers = []struct {
	name   string
	render func(*Request) ([]byte, error)
}{
	{FileREADME, README},
	{FileOU, OUInstructions},
	{FilePolicy, DelegationPolicy},
	{FileRoleCFN, VendorRoleCFN},
	{FileRoleTF, VendorRoleTF},
}

// Status is what happened to one file.
type Status int

// The three outcomes. Unchanged exists so a re-run reports honestly rather than
// claiming to have written what it did not: CLAUDE.md rule 4 asks for ensure
// semantics, and "ensured" and "created" are different sentences.
const (
	Created Status = iota
	Unchanged
	Replaced
)

func (s Status) String() string {
	switch s {
	case Created:
		return "created"
	case Unchanged:
		return "unchanged"
	case Replaced:
		return "replaced"
	}
	return "unknown"
}

// WrittenFile is one line of the plan or of the result.
type WrittenFile struct {
	Name   string
	Status Status
	Bytes  int
}

// Result is what Write or Plan produced.
type Result struct {
	// Dir is the directory as automat resolved it, so the operator can see where
	// a relative path landed.
	Dir   string
	Files []WrittenFile
}

// String renders the result for the CLI.
func (res *Result) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", res.Dir)
	for _, f := range res.Files {
		fmt.Fprintf(&b, "  %-9s %-24s %d bytes\n", f.Status, f.Name, f.Bytes)
	}
	return b.String()
}

// Options control where the bundle goes and whether an existing one may be
// overwritten.
type Options struct {
	// Dir is the directory to write into. It is created if it does not exist.
	Dir string
	// Force permits replacing a file whose contents differ from what automat
	// would write. Without it, a differing file is an error: the operator may
	// have edited the bundle after generating it — narrowing the trust principal
	// by hand, say — and silently discarding that is the kind of help nobody
	// asks for.
	Force bool
}

// Plan renders the bundle and reports what writing it would do, touching nothing.
//
// This is the plan half of the plan/apply split CLAUDE.md rule 5 asks to exist
// from Phase 2 onward. It is here early because it costs nothing: the renderers
// are pure functions of the Request, so the plan is the real output, not a
// prediction of it.
func Plan(r *Request, opts Options) (*Result, error) {
	return write(r, opts, false)
}

// Write renders the bundle and writes it.
func Write(r *Request, opts Options) (*Result, error) {
	return write(r, opts, true)
}

func write(r *Request, opts Options, apply bool) (*Result, error) {
	if opts.Dir == "" {
		return nil, errors.New("no output directory — pass --out with a directory to write the bundle into")
	}
	// Render everything before creating anything. A bundle is only useful whole:
	// a directory holding a role template and no delegation policy is a request
	// central IT would half-approve.
	rendered := make(map[string][]byte, renderersCount)
	for _, rd := range renderers {
		data, err := rd.render(r)
		if err != nil {
			return nil, err
		}
		rendered[rd.name] = data
	}

	abs, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory %s: %w", quote(opts.Dir), err)
	}
	res := &Result{Dir: abs}

	if !apply {
		root, cleanup, oerr := openExisting(abs)
		if oerr != nil {
			return nil, oerr
		}
		defer cleanup()
		for _, rd := range renderers {
			st, serr := statusOf(root, rd.name, rendered[rd.name], opts.Force)
			if serr != nil {
				return nil, serr
			}
			res.Files = append(res.Files, WrittenFile{rd.name, st, len(rendered[rd.name])})
		}
		return res, nil
	}

	// 0700, not 0755: one of these files carries the ExternalId, and a bundle in
	// a world-readable directory hands it to every account on a shared login
	// host — which is exactly where a research-computing operator runs this.
	if mkerr := os.MkdirAll(abs, dirMode); mkerr != nil {
		return nil, fmt.Errorf("create output directory %s: %w", quote(abs), mkerr)
	}
	// Everything past this point resolves against this handle, not against the
	// name — see the package note above.
	root, oerr := os.OpenRoot(abs)
	if oerr != nil {
		return nil, fmt.Errorf("open output directory %s: %w", quote(abs), oerr)
	}
	defer func() { _ = root.Close() }()

	// A pre-existing directory may be group- or world-readable, and MkdirAll
	// leaves an existing directory's mode alone. Tighten it, and say so rather
	// than changing an operator's filesystem quietly.
	if terr := tighten(root, res); terr != nil {
		return nil, terr
	}

	for _, rd := range renderers {
		data := rendered[rd.name]
		st, serr := statusOf(root, rd.name, data, opts.Force)
		if serr != nil {
			return nil, serr
		}
		if st != Unchanged {
			if werr := writeFile(root, rd.name, data); werr != nil {
				return nil, werr
			}
		}
		res.Files = append(res.Files, WrittenFile{rd.name, st, len(data)})
	}
	return res, nil
}

// openExisting opens abs as a root if it exists, for the plan path. A plan for a
// directory that does not exist yet is still a valid plan — everything is
// Created — so a missing directory yields a nil root rather than an error.
func openExisting(abs string) (*os.Root, func(), error) {
	root, err := os.OpenRoot(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, func() {}, nil
		}
		return nil, nil, fmt.Errorf("open output directory %s: %w", quote(abs), err)
	}
	return root, func() { _ = root.Close() }, nil
}

// statusOf decides what will happen to one file, and is the only place that
// refuses.
func statusOf(root *os.Root, name string, want []byte, force bool) (Status, error) {
	if root == nil {
		return Created, nil
	}
	// Lstat, not Stat: a symlink here must be reported as a symlink. os.Root
	// would refuse to follow one leading outside the directory, but one leading
	// *inside* it would be followed, and a bundle file that is secretly a link to
	// another bundle file is not something to write through either way.
	fi, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Created, nil
		}
		return Created, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return Created, fmt.Errorf("%s exists and is not a regular file (mode %s) — "+
			"automat will not write through it; remove it or choose another --out directory",
			name, fi.Mode())
	}
	got, err := readFile(root, name)
	if err != nil {
		return Created, err
	}
	if bytes.Equal(got, want) {
		return Unchanged, nil
	}
	if !force {
		return Replaced, fmt.Errorf("%s already exists with different contents — "+
			"if you edited the bundle by hand, those edits would be lost; "+
			"re-run with --force to overwrite, or write to an empty directory", name)
	}
	return Replaced, nil
}

func readFile(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	// A bundle file is a few kilobytes. The limit is not about memory; it stops a
	// comparison against something enormous that was put here to be compared
	// against, and it cannot cause a wrong answer: a file over the limit is not
	// equal to what automat renders, which is the conservative outcome.
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

// writeFile replaces name's contents through root.
//
// O_TRUNC rather than write-to-temp-and-rename: os.Root has Rename, but the
// failure mode a rename protects against — a half-written file — is not the one
// that matters here. Nothing consumes the bundle programmatically; a human reads
// it and an operator applies it, and a truncated YAML template fails to deploy
// rather than deploying something partial. The straight write is the one whose
// permissions are easy to reason about.
//
// The mode is fixed on the descriptor rather than trusted from O_CREATE, for two
// reasons that both end with the ExternalId being readable: O_CREATE's mode is
// masked by the process umask, and it is ignored entirely for a file that already
// exists — which may be 0644 from a copy, or from a version of this code that
// wrote it that way. Chmod on the open file rather than on the path so there is no
// window between the two operations, and no second name resolution.
func writeFile(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Chmod(fileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("set permissions on %s (the bundle contains an ExternalId): %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// tighten narrows the bundle directory's mode if it is readable by anyone but its
// owner, and records that it did.
func tighten(root *os.Root, res *Result) error {
	d, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("inspect output directory %s: %w", quote(res.Dir), err)
	}
	defer func() { _ = d.Close() }()
	fi, err := d.Stat()
	if err != nil {
		return fmt.Errorf("inspect output directory %s: %w", quote(res.Dir), err)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := d.Chmod(dirMode); err != nil {
		return fmt.Errorf("restrict permissions on %s (it is mode %s, and the bundle contains an "+
			"ExternalId): %w", quote(res.Dir), fi.Mode().Perm(), err)
	}
	res.Dir += fmt.Sprintf(" (permissions narrowed from %s to %s)", fi.Mode().Perm(), dirMode.Perm())
	return nil
}

// FileNames lists the bundle's files, sorted, for tests and for `--help`.
func FileNames() []string {
	names := make([]string, 0, len(renderers))
	for _, rd := range renderers {
		names = append(names, rd.name)
	}
	sort.Strings(names)
	return names
}
