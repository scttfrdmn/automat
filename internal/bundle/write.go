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

	"github.com/scttfrdmn/automat/internal/safeio"
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
// write five files into a path the operator named, and a component of that path — or
// an entry inside it — can be a symlink. `os.Root` closes the escape: the root is
// held as an open directory handle, so a symlink leading out of it fails with "path
// escapes from parent" instead of writing somewhere else.
//
// # What is actually at stake here, since it is not confidentiality
//
// Every protection below was originally justified by one sentence: the bundle
// contains a live `sts:ExternalId`. It no longer does — the templates declare the
// value as a deploy-time input and central IT generates it (see externalid.go), so
// there is no secret in this directory at all. That change removed the reason this
// file gave for everything it does, and the reason it gives now is a better one that
// was true the whole time.
//
// These five files are a grant. Central IT reads them and applies them, and what
// comes out is an IAM role in a management account trusting another account. So the
// property that matters is the *integrity* of the file at the moment a human reviews
// it and at the moment Terraform or CloudFormation consumes it. Anyone who can
// redirect or substitute one of these writes does not learn a secret; they choose the
// policy someone else is about to deploy — widen the trust principal, drop the
// ExternalId condition, add an action. That is strictly worse than the leak this file
// used to be organized around, and every mechanism here (write through a descriptor
// that was inspected, refuse a symlink, refuse a hardlink, refuse a non-regular file)
// defends it unchanged.
//
// What genuinely did weaken is the confidentiality argument for the 0600 file mode,
// the 0700 directory, and the generated .gitignore. The bundle still holds account
// ids, an organization id, and the requester's address — organizational detail worth
// not scattering, but not a credential, and an operator who commits one has not
// leaked a secret. Those three are kept as a conservative default for a tool's own
// output rather than as a defense, and they are labelled that way below instead of
// borrowing urgency from a threat that is gone.
//
// What `os.Root` does NOT do is make the surrounding code safe, and an earlier
// version of this comment claimed it did. `os.Root` guarantees that operations stay
// inside a root; it says nothing about whether the root is the right directory, and
// nothing about the gap between checking a name and acting on it. Two defects here
// came from believing otherwise:
//
//   - Creating the directory by name and then rooting it by name lets an attacker
//     swap a symlink in between, so the root itself becomes theirs. openOutputDir
//     roots the parent once and creates through that handle instead.
//   - Deciding what to do with a file by name (statusOf) and then writing to that
//     name (writeFile) resolves it twice, so the write can be redirected to a
//     different entry. It cannot leave the root, which bounds the damage to one
//     bundle file overwriting another — but automat then reports having written a
//     file whose name now holds something else, which is a false report about a
//     grant. Both now share a single descriptor.
//
// The rule this package follows: resolve a path once, then operate on the
// descriptor. A check on a name followed by an action on the same name is two
// different objects however narrow the window looks.
//
// os.Root's own WriteFile is Go 1.25; the module floor is 1.24, so writes go
// through Root.OpenFile.

// The five files, in the order they are reported. README first because it is the
// one a reviewer opens.
const (
	FileREADME  = "README.md"
	FileOU      = "ou.md"
	FilePolicy  = "delegation-policy.json"
	FileRoleCFN = "vendor-role.cfn.yaml"
	FileRoleTF  = "vendor-role.tf"
	// fileGitignore is written into the bundle directory, not read from it. An
	// operator running `automat setup --out ./bundle` inside a checkout -- the
	// obvious thing to do -- otherwise commits the accounts, the organization id,
	// and the requester's address into a repository that may be public. Not a
	// credential (see gitignoreContents), and cheap enough to prevent rather than
	// mention.
	fileGitignore  = ".gitignore"
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

// The four outcomes. Unchanged exists so a re-run reports honestly rather than
// claiming to have written what it did not: CLAUDE.md rule 4 asks for ensure
// semantics, and "ensured" and "created" are different sentences.
//
// Tightened is the case that would otherwise hide inside Unchanged: the contents
// already match but the mode did not, so automat changed the operator's filesystem.
// Rolling that into "unchanged" would report a permission repair as a no-op, and a
// tool that silently adjusts modes is one an operator cannot reason about.
const (
	Created Status = iota
	Unchanged
	Replaced
	Tightened
)

func (s Status) String() string {
	switch s {
	case Created:
		return "created"
	case Unchanged:
		return "unchanged"
	case Replaced:
		return "replaced"
	case Tightened:
		return "permissions narrowed"
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
	// a relative path landed. It is a path and nothing else: prose was appended to
	// it once, which broke anything doing `cd "$(automat setup --out X | head -1)"`
	// and made the documented meaning of the field false.
	Dir string
	// Notes are things the operator should know that are not about a single file —
	// a permission change on the directory, for instance.
	Notes []string
	Files []WrittenFile
}

// String renders the result for the CLI.
func (res *Result) String() string {
	var b strings.Builder
	// The first line is the path alone, so a script can take it. Notes go after the
	// file list rather than on this line for the same reason.
	fmt.Fprintf(&b, "%s\n", res.Dir)
	for _, f := range res.Files {
		fmt.Fprintf(&b, "  %-20s %-24s %d bytes\n", f.Status, f.Name, f.Bytes)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(&b, "\nNote: %s\n", n)
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
	if err := checkOutputPath(opts.Dir); err != nil {
		return nil, err
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

	root, oerr := openOutputDir(abs)
	if oerr != nil {
		return nil, oerr
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
		st, werr := ensureFile(root, rd.name, data, opts.Force)
		if werr != nil {
			// A partial bundle is worse than none: the header above says a bundle is
			// only useful whole, and a directory holding a role template from this run
			// beside a delegation policy from the last one is a grant nobody composed.
			// Say exactly which files exist so the operator is not guessing.
			return nil, partialBundleError(res, rd.name, werr)
		}
		res.Files = append(res.Files, WrittenFile{rd.name, st, len(data)})
	}

	// Written last and reported like the rest: an operator who sees it appear knows
	// why it is there, and one who deletes it has made a choice rather than an
	// oversight.
	st, gerr := ensureFile(root, fileGitignore, gitignoreContents, opts.Force)
	if gerr != nil {
		return nil, partialBundleError(res, fileGitignore, gerr)
	}
	res.Files = append(res.Files, WrittenFile{fileGitignore, st, len(gitignoreContents)})
	return res, nil
}

// gitignoreContents ignores everything, including itself.
//
// The text is generated output, so a stale claim in it is not a stale comment — it is
// automat telling an operator something false in a file automat wrote. This used to
// say the directory contained a shared secret. It does not: every file here is
// regenerable from the config, and the ExternalId is supplied at deploy time by
// whoever applies the templates.
//
// The file stays, with the honest reason. A bundle names accounts, an organization,
// and a person, and none of that belongs in a research group's public repository — but
// committing one is an untidiness, not an incident, and the note says so rather than
// implying a credential is at stake. Overstating it is not a harmless exaggeration: an
// operator who checks the claim, finds no secret, and concludes automat's warnings are
// inflated will discount the next one, which may be about the grant.
var gitignoreContents = []byte(`# Written by automat. These files are generated from your configuration and can be
# regenerated at any time, so there is nothing here worth committing -- and they name
# your accounts, your organization, and a contact, which is detail a public repository
# does not need. No secret is in this directory: the sts:ExternalId is generated by
# whoever deploys the role, not by automat.
*
`)

// ensureFile brings one bundle file to its intended contents and mode, and reports
// what it had to do. The descriptor is opened once and both the decision and the
// write use it.
func ensureFile(root *os.Root, name string, data []byte, force bool) (Status, error) {
	f, st, err := inspectForWrite(root, name, data, force)
	if f != nil {
		defer func() { _ = f.Close() }()
	}
	if err != nil {
		return st, err
	}
	if st == Unchanged || st == Tightened {
		return st, nil
	}
	if err := writeThrough(f, name, data); err != nil {
		return st, err
	}
	return st, nil
}

// partialBundleError reports a mid-loop failure together with what the directory now
// holds.
//
// Rendering happens before any write, so a bad request cannot produce a partial
// bundle — but a write failure partway through can, and an operator who changed the
// trust principal would otherwise be left with a directory where the CloudFormation
// template grants one thing and the Terraform beside it grants another, with nothing
// marking which is which. Central IT reviews whichever one they open. A later run
// reports the stale files as unchanged, so re-running does not converge on its own.
func partialBundleError(res *Result, failed string, cause error) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%v", cause)
	if len(res.Files) == 0 {
		return errors.New(b.String())
	}
	b.WriteString("\n\nThe bundle is now incomplete. These files were written by this run:")
	for _, f := range res.Files {
		fmt.Fprintf(&b, "\n  %s (%s)", f.Name, f.Status)
	}
	fmt.Fprintf(&b, "\n  %s and any files after it were not.", failed)
	b.WriteString("\nA bundle is only useful whole, and the files above may disagree with the " +
		"older ones beside them about what is being granted. Fix the cause, then " +
		"re-run with --force to rewrite the whole directory: a plain re-run reports " +
		"the stale files as unchanged and will not converge.")
	return errors.New(b.String())
}

// checkOutputPath refuses a --out path containing a control character.
//
// Every other operator-supplied value in this package is quoted where it is rendered
// (AUDIT-0 M1), and Result.Dir is the one that cannot be: the first line of Write's
// output is documented as the bare path so `cd "$(automat setup --out X | head -1)"`
// works, and putting it through %q would break the contract the Result.Dir comment
// makes. Quoting is the wrong end of this anyway — a path is not a rejected value
// being reported back, it is a path the operator is about to use.
//
// So the input is refused instead. A directory whose name contains a newline is
// creatable on Linux and darwin (verified), which makes `--out $'out\n  CREATED
// role.yaml  9999 bytes'` a plausible-looking extra line in automat's own file list,
// and an ESC byte can erase the lines above it. That matters because the forged
// output is the report of what automat wrote: a line claiming a file was created,
// or an ESC hiding one that was, is how an operator sends a bundle they never saw.
//
// Only control bytes are refused, not spaces or unusual characters: an operator with
// a directory called "AWS Onboarding 2026" has done nothing wrong, and a charset
// allowlist on a filesystem path would refuse legitimate non-ASCII paths for no
// security gain. A control byte is the whole class that can move a cursor or start
// a line.
func checkOutputPath(dir string) error {
	for i := 0; i < len(dir); i++ {
		if b := dir[i]; b < 0x20 || b == 0x7f {
			return fmt.Errorf("the output directory path contains a control character (byte %#02x at "+
				"offset %d), and automat prints that path as the first line of its output so a script "+
				"can use it — a newline or an escape byte there forges a line of automat's own "+
				"report of which files it wrote. "+
				"Pass --out with a path containing no control characters", b, i)
		}
	}
	return nil
}

// openOutputDir creates the output directory and returns a root confined to it.
//
// The obvious spelling — os.MkdirAll(abs) then os.OpenRoot(abs) — is wrong, and
// wrong in exactly the way this package's note claims to defend against. Both calls
// resolve the *name*, so between them an attacker who can write the parent replaces
// the new directory with a symlink and os.OpenRoot roots itself wherever the link
// points. Every "confined" write then lands there — and, worse, the operator then
// reviews and sends whatever is at the name they typed, which is now someone else's
// directory holding someone else's policy. os.Root prevents escaping a root; it
// cannot help if the root itself is the attacker's.
//
// A planted symlink needs no race at all: filepath.Abs does not resolve symlinks,
// so MkdirAll on an existing link succeeds silently and OpenRoot follows it.
//
// So the parent is rooted once, and the directory is created and re-rooted through
// that handle. Root.Mkdir and Root.OpenRoot resolve against the parent's descriptor,
// so creation and rooting share one fd chain and there is no name to swap in
// between. An existing final component is Lstat'ed through the same handle and
// refused if it is a symlink — the operator named a directory, and on a shared host
// they did not choose what that name already points to.
func openOutputDir(abs string) (*os.Root, error) {
	parent, base := filepath.Dir(abs), filepath.Base(abs)
	// The parent must already exist. Creating a chain of parents is a different
	// operation with a different blast radius, and an operator who mistyped a path
	// is better served by an error naming the missing directory than by automat
	// silently building a tree.
	proot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open the parent of the output directory %s: %w\n"+
			"automat creates the bundle directory but not the path leading to it; "+
			"create %s first, or pass --out under a directory that exists",
			quote(abs), err, quote(parent))
	}
	defer func() { _ = proot.Close() }()

	// 0700, not 0755. Not a confidentiality defense -- there is no secret here --
	// but a research-computing operator runs this on a shared login host, and a
	// bundle directory every account can read is one every account can also
	// enumerate for account ids and contacts. Conservative default for a tool's
	// own output.
	switch mkerr := proot.Mkdir(base, dirMode); {
	case mkerr == nil:
	case errors.Is(mkerr, fs.ErrExist):
		// Re-running into an existing bundle directory is the normal idempotent
		// case (CLAUDE.md rule 4). But "it exists" must not mean "it is a
		// directory": a symlink here is the pre-planted case above, and Lstat
		// through the parent's handle is what distinguishes them.
		fi, lerr := proot.Lstat(base)
		if lerr != nil {
			return nil, fmt.Errorf("inspect the output directory %s: %w", quote(abs), lerr)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			return nil, fmt.Errorf("the output directory %s is a symbolic link (to %s) — "+
				"automat will not write a grant through a link it did not create, because "+
				"the name you passed and the directory it resolves to are not the same "+
				"choice, and you would review whichever one the name points at when you "+
				"send it; pass --out with a real directory, or remove the link",
				quote(abs), safeio.LinkTarget(parent, base))
		case !fi.IsDir():
			return nil, fmt.Errorf("the output directory %s exists and is not a directory "+
				"(mode %s) — remove it or pass a different --out", quote(abs), fi.Mode())
		}
	default:
		return nil, fmt.Errorf("create output directory %s: %w", quote(abs), mkerr)
	}

	// Rooted through the parent's descriptor rather than by name, so this is the
	// directory just created or verified, whatever the name means now.
	root, err := proot.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open output directory %s: %w", quote(abs), err)
	}
	return root, nil
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
//
// It is name-based and used only by the plan path, where nothing is written and a
// second resolution therefore cannot redirect anything. The apply path uses
// inspectForWrite, which keeps the descriptor it judged.
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

// inspectForWrite opens one bundle file and decides what to do with it, returning
// the descriptor it made that decision about.
//
// The descriptor is the point. Deciding by name and then writing by name resolves
// the path twice, so the file that was judged and the file that is written need not
// be the same one. Everything below inspects this single open file: fstat rather than
// lstat, and the same fd is handed to writeThrough.
//
// The caller closes the returned file whenever it is non-nil, including alongside an
// error.
func inspectForWrite(root *os.Root, name string, want []byte, force bool) (*os.File, Status, error) {
	// O_CREATE|O_EXCL first: if this succeeds the file did not exist, which is both
	// the common case and the one with nothing to inspect. It also means the
	// existence check and the creation are a single atomic operation rather than a
	// test followed by a create.
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err == nil {
		return f, Created, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, Created, fmt.Errorf("write %s: %w", name, err)
	}

	// It exists. Lstat through the root first, because opening it is what must be
	// avoided if it is a symlink: os.Root refuses a link out of the root, but would
	// follow one pointing at another file inside it.
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, Created, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, Created, fmt.Errorf("%s exists and is not a regular file (mode %s) — "+
			"automat will not write through it; remove it or choose another --out directory",
			name, fi.Mode())
	}

	// safeio.OpenNonBlock covers the FIFO the Lstat above cannot: one swapped in
	// after the check. Without it this open never returns — opening a pipe waits for
	// the other end — so automat hangs with no output rather than refusing. It is a
	// no-op on a regular file, which is all this open is meant to reach.
	f, err = root.OpenFile(name, os.O_RDWR|safeio.OpenNonBlock, fileMode)
	if err != nil {
		return nil, Created, fmt.Errorf("open %s: %w", name, err)
	}
	// Re-stat on the descriptor. The Lstat above resolved a name; this resolves the
	// object that is actually open, which is the one about to be written.
	st, err := f.Stat()
	if err != nil {
		return f, Created, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !st.Mode().IsRegular() {
		return f, Created, fmt.Errorf("%s is not a regular file (mode %s) — "+
			"automat will not write through it", name, st.Mode())
	}
	// Tie the name that was inspected to the descriptor that was opened. Without
	// this the two resolutions above are independent, and whoever can write this
	// directory decides which file the second one lands on — the Lstat passes on a
	// regular file they then replace with a link to somewhere else. os.Root does not
	// close this: verified against go1.24, it follows a symlink whose target is
	// inside the root and ignores O_NOFOLLOW in the flags it is handed.
	if !os.SameFile(fi, st) {
		return f, Created, fmt.Errorf("%s changed while automat was opening it — the file "+
			"inspected and the file opened are not the same one. Nothing was written; "+
			"investigate before retrying, because on a shared host this is what a swapped "+
			"path looks like", name)
	}
	if n, ok := safeio.LinkCount(st); ok && n > 1 {
		// A hardlink is a regular file by every mode check, and Lstat cannot tell
		// one from an ordinary file. Writing through it truncates whatever else
		// shares the inode, destroying a file automat was never pointed at.
		return f, Created, fmt.Errorf("%s has %d hard links — writing it would overwrite "+
			"whatever else shares that file; "+
			"remove %s or choose another --out directory", name, n, name)
	}

	got, err := io.ReadAll(io.LimitReader(f, maxCompareBytes))
	if err != nil {
		return f, Created, fmt.Errorf("read %s: %w", name, err)
	}
	if bytes.Equal(got, want) {
		// Unchanged in content is not unchanged in mode. A bundle copied with
		// `cp` or unpacked from a tar arrives 0644; ensure semantics (CLAUDE.md
		// rule 4) cover the mode, not just the bytes, so a re-run converges on
		// both.
		if st.Mode().Perm()&0o077 != 0 {
			if cerr := f.Chmod(fileMode); cerr != nil {
				return f, Unchanged, fmt.Errorf("restrict permissions on %s (it is mode %s, "+
					"readable beyond you): %w", name, st.Mode().Perm(), cerr)
			}
			return f, Tightened, nil
		}
		return f, Unchanged, nil
	}
	if !force {
		return f, Replaced, fmt.Errorf("%s already exists with different contents — "+
			"if you edited the bundle by hand, those edits would be lost; "+
			"re-run with --force to overwrite, or write to an empty directory", name)
	}
	return f, Replaced, nil
}

// maxCompareBytes bounds the read used to decide whether a file already matches.
// The limit is not about memory; it stops a comparison against something enormous
// that was put here to be compared against, and it cannot cause a wrong answer: a
// file over the limit is not equal to what automat renders, which is the
// conservative outcome.
const maxCompareBytes = 1 << 20

func readFile(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	// A bundle file is a few kilobytes; see maxCompareBytes.
	data, err := io.ReadAll(io.LimitReader(f, maxCompareBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

// writeThrough writes data to an already-open descriptor and fixes its mode.
//
// It takes the *os.File rather than a name because the caller has already inspected
// that file, and re-resolving the name would inspect one object and write to
// another. os.Root bounds where a redirected write can land — inside the root — but
// "the delegation policy silently overwritten by a role template, so the reviewer
// approves a file that is not the one automat reported writing" is not an outcome
// worth allowing because it is bounded.
//
// O_TRUNC rather than write-to-temp-and-rename: os.Root.Rename is Go 1.25 and the
// module floor is 1.24. The failure mode a rename protects against — a half-written
// file — also matters less here than it looks: nothing consumes the bundle
// programmatically, a human reads it, and a truncated YAML template fails to deploy
// rather than deploying something partial.
//
// The mode is fixed on the descriptor rather than trusted from O_CREATE, for two
// reasons that both end with the file being wider than intended: O_CREATE's mode is
// masked by the process umask, and it is ignored entirely for a file that already
// exists — which may be 0644 from a copy. fchmod on the open file has no window and
// no second name resolution, and it is stronger than os.Root.Chmod, whose own
// documentation notes a race if the target becomes a symlink mid-operation.
//
// Chmod precedes Write, which is what makes a write to an inode automat's user does
// not own fail closed: fchmod returns EPERM for a non-owner, so a file automat
// cannot control the mode of is a file it does not write.
func writeThrough(f *os.File, name string, data []byte) error {
	if err := f.Chmod(fileMode); err != nil {
		return fmt.Errorf("set permissions on %s: %w", name, err)
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// tighten narrows the bundle directory's mode if it is readable by anyone but its
// owner, and records that it did.
//
// Two things this deliberately does not do, both learned from getting them wrong:
//
// It does not Chmod(0700). The guard tests Perm()&0o077, which ignores setgid,
// setuid, and sticky, but Chmod writes all twelve bits — so tightening a 2750 project
// directory silently cleared setgid and new files stopped inheriting the group, and
// tightening 1777 scratch space cleared sticky. Clearing bits nobody asked about is
// not a security improvement; it is an unrelated change to someone's filesystem made
// under cover of one. The mask preserves the high bits and clears only group and
// other.
//
// It does not tighten a directory holding files that are not automat's. --out at an
// existing directory with unrelated content used to relock all of it: pointing it at
// a web root made the served files unreadable, and at /tmp made the machine's shared
// scratch space private. automat is right to want 0700 for its own output; it has no
// standing to impose that on a directory whose purpose it does not know.
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

	// Refuse rather than relock when the directory holds someone else's files. The
	// operator gets a directory they control instead of a surprise.
	foreign, err := foreignEntries(d)
	if err != nil {
		return fmt.Errorf("inspect output directory %s: %w", quote(res.Dir), err)
	}
	if len(foreign) > 0 {
		return fmt.Errorf("the output directory %s is mode %s and holds files that are not "+
			"part of a bundle (%s) — automat writes its own output mode 0700 and would have "+
			"to narrow this directory to do so, which it will not do to a directory holding "+
			"other content; pass --out with a new or empty directory",
			quote(res.Dir), fi.Mode().Perm(), strings.Join(foreign, ", "))
	}

	// Preserve setgid, setuid, and sticky; clear only group and other.
	want := fi.Mode().Perm()&^0o077 | 0o700
	if err := d.Chmod(want); err != nil {
		return fmt.Errorf("restrict permissions on %s (it is mode %s, readable beyond "+
			"you): %w", quote(res.Dir), fi.Mode().Perm(), err)
	}
	res.Notes = append(res.Notes, fmt.Sprintf("permissions on %s narrowed from %s to %s",
		quote(res.Dir), fi.Mode().Perm(), want))
	return nil
}

// foreignEntries lists entries in the output directory that no bundle run would have
// put there, sorted, capped so an enormous directory produces a readable error.
func foreignEntries(d *os.File) ([]string, error) {
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	ours := make(map[string]bool, len(renderers)+1)
	for _, rd := range renderers {
		ours[rd.name] = true
	}
	ours[fileGitignore] = true
	var out []string
	for _, n := range names {
		if !ours[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	const maxNamed = 5
	if len(out) > maxNamed {
		extra := len(out) - maxNamed
		out = append(out[:maxNamed:maxNamed], fmt.Sprintf("and %d more", extra))
	}
	return out, nil
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
