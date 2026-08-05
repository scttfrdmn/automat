// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWriteProducesTheWholeBundle(t *testing.T) {
	dir := t.TempDir()
	res, err := Write(validRequest(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The five rendered files plus the generated .gitignore, which is part of the
	// bundle rather than an extra: it is what stops an operator committing the
	// ExternalId when they run this inside a checkout.
	if len(res.Files) != renderersCount+1 {
		t.Fatalf("wrote %d files, want %d", len(res.Files), renderersCount+1)
	}
	for _, f := range res.Files {
		if f.Status != Created {
			t.Errorf("%s: status %s on a first write", f.Name, f.Status)
		}
		if f.Bytes == 0 {
			t.Errorf("%s: 0 bytes", f.Name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != renderersCount+1 {
		t.Errorf("%d entries in the directory, want %d", len(entries), renderersCount+1)
	}
	for _, name := range FileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestWrittenFilesAreOwnerOnly is the ExternalId's only filesystem defense: the
// bundle is generated on a shared login host as often as not, and a 0644
// delegation bundle hands the ExternalId to every account on the machine.
func TestWrittenFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Write(validRequest(), Options{Dir: dir}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("directory mode %s, want 0700", got)
	}
	for _, name := range FileNames() {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode %s, want 0600", name, got)
		}
	}
}

// TestWriteTightensAPreExistingLooseDirectory covers the case MkdirAll does not:
// the operator ran `mkdir -p ~/bundles/x` first, or their umask is 022 and the
// parent was made by something else.
func TestWriteTightensAPreExistingLooseDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// os.Mkdir applies the umask; force it.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Write(validRequest(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("directory mode %s, want it narrowed to 0700", got)
	}
	// And it must say so: changing an operator's filesystem quietly is how a tool
	// loses trust.
	// Reported in Notes, not appended to Dir: Dir is documented as the path and a
	// caller doing `cd "$(... | head -1)"` must keep working.
	if !strings.Contains(strings.Join(res.Notes, "\n"), "narrowed") {
		t.Errorf("the result does not mention narrowing the permissions: %#v", res.Notes)
	}
	if strings.Contains(res.Dir, "narrowed") {
		t.Errorf("Dir carries prose instead of a path: %q", res.Dir)
	}
}

// TestWriteOverwritesALooseExistingFile covers O_CREATE's mode being ignored for
// an existing file: a bundle regenerated over a 0644 file must not stay 0644.
func TestWriteOverwritesALooseExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, FileRoleCFN)
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(validRequest(), Options{Dir: dir, Force: true}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("%s mode %s after overwrite, want 0600 — the ExternalId is in this file",
			FileRoleCFN, got)
	}
}

// TestRewritingAnUnchangedBundleIsIdempotent is CLAUDE.md rule 4 for this
// command, and it must report honestly: "unchanged" and "created" are different
// sentences, and a tool that says it wrote something it did not is a tool whose
// output nobody can use to reason.
func TestRewritingAnUnchangedBundleIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	r := validRequest()
	if _, err := Write(r, Options{Dir: dir}); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	before := snapshot(t, dir)

	res, err := Write(r, Options{Dir: dir})
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}
	for _, f := range res.Files {
		if f.Status != Unchanged {
			t.Errorf("%s: status %s on a re-run with identical input, want unchanged", f.Name, f.Status)
		}
	}
	if after := snapshot(t, dir); !equalSnapshots(before, after) {
		t.Error("a re-run changed the bundle's contents")
	}
	// And without --force, since nothing differs.
	if _, err := Write(r, Options{Dir: dir, Force: false}); err != nil {
		t.Errorf("a re-run required --force: %v", err)
	}
}

// TestWriteRefusesToDiscardAHandEditWithoutForce protects the case where central
// IT asked for a change and the operator made it in the bundle directly —
// narrowing the trust principal, say. Silently reverting that is the kind of help
// nobody asks for.
func TestWriteRefusesToDiscardAHandEditWithoutForce(t *testing.T) {
	dir := t.TempDir()
	r := validRequest()
	if _, err := Write(r, Options{Dir: dir}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	path := filepath.Join(dir, FileRoleCFN)
	edited := "# hand-edited by central IT\n"
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Write(r, Options{Dir: dir})
	if err == nil {
		t.Fatal("Write overwrote a hand-edited file without --force")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the error does not say how to proceed: %v", err)
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != edited {
		t.Error("the hand-edited file was modified despite the refusal")
	}

	if _, err := Write(r, Options{Dir: dir, Force: true}); err != nil {
		t.Fatalf("Write with --force: %v", err)
	}
	got, rerr = os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) == edited {
		t.Error("--force did not overwrite the hand-edited file")
	}
}

// TestWriteRefusesASymlink is the A1 finding's direct test. A bundle file that is
// a symlink is a request to write the ExternalId somewhere the operator did not
// name — the classic form being a link planted in a shared or predictable output
// directory before the operator runs the command.
func TestWriteRefusesASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "bundle")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "captured")

	for _, tc := range []struct{ name, link string }{
		{"outside the directory", target},
		{"absolute path outside", "/tmp/automat-should-not-be-written"},
		{"inside the directory", filepath.Join(dir, FileREADME)},
		{"parent traversal", filepath.Join(dir, "..", "captured")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, FileRoleCFN)
			_ = os.Remove(path)
			if err := os.Symlink(tc.link, path); err != nil {
				t.Fatal(err)
			}
			_, err := Write(validRequest(), Options{Dir: dir, Force: true})
			if err == nil {
				t.Fatal("Write followed a symlink")
			}
			if !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("the error does not explain the refusal: %v", err)
			}
			if _, serr := os.Lstat(target); serr == nil {
				t.Errorf("Write created %s through the symlink", target)
			}
			_ = os.Remove(path)
		})
	}
}

// TestWriteRefusesADirectoryInAFilesPlace is the same refusal for the other
// non-regular case, which is what an operator gets by running the command twice
// with a typo'd --out.
func TestWriteRefusesADirectoryInAFilesPlace(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, FilePolicy), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Write(validRequest(), Options{Dir: dir, Force: true})
	if err == nil {
		t.Fatal("Write accepted a directory where a file belongs")
	}
	if !strings.Contains(err.Error(), FilePolicy) {
		t.Errorf("the error does not name the offending path: %v", err)
	}
}

// TestWriteRefusesASymlinkedOutputDirectory reverses what this test used to assert.
//
// It previously accepted a symlinked --out on the reasoning that "the operator named
// it". That reasoning does not hold: the operator named a *name*, and on a shared
// login host — the environment this tool is built for — they did not choose what that
// name resolves to. An attacker who can write the parent directory pre-plants the
// link and receives the ExternalId, with no race required, because filepath.Abs does
// not resolve symlinks and MkdirAll on an existing link succeeds silently.
//
// Only the final component is refused. Symlinks *above* it are resolved normally and
// must keep working, because they are everywhere and are not the operator's choice
// either: /tmp is a symlink to /private/tmp on darwin, and home directories are
// frequently symlinked on clustered filesystems. Refusing those would make the tool
// unusable for the audience it is for. The distinction is that a link in the parent
// path is resolved once, before the root is established, whereas a link at the leaf
// is the root.
func TestWriteRefusesASymlinkedOutputDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	base := t.TempDir()
	real := filepath.Join(base, "attacker-dest")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := Write(validRequest(), Options{Dir: link})
	if err == nil {
		t.Fatal("Write wrote the ExternalId through a symlinked output directory")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("the error does not say the path is a link, so the operator cannot tell "+
			"what to fix: %v", err)
	}
	// Nothing may have been written through it.
	entries, rerr := os.ReadDir(real)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Errorf("the refusal still wrote %d files into the link target: %v", len(entries), entries)
	}
}

// TestWriteFollowsSymlinksAboveTheOutputDirectory is the other side of the line, and
// it is the case that must not regress: a link in the path leading to --out is
// ordinary and must be resolved, or the tool refuses to run under /tmp on darwin and
// under most clustered home directories.
func TestWriteFollowsSymlinksAboveTheOutputDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real-parent")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked-parent")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// --out is a directory *inside* a symlinked parent.
	out := filepath.Join(link, "bundle")
	if _, err := Write(validRequest(), Options{Dir: out}); err != nil {
		t.Fatalf("Write refused a symlink above the output directory: %v", err)
	}
	for _, name := range FileNames() {
		if _, err := os.Stat(filepath.Join(real, "bundle", name)); err != nil {
			t.Errorf("%s did not land in the resolved directory: %v", name, err)
		}
	}
}

// TestWriteIsAllOrNothingOnAnInvalidRequest: a partial bundle is worse than none.
// Central IT receiving a role template without a delegation policy approves half a
// grant, and the operator does not know which half is missing.
func TestWriteIsAllOrNothingOnAnInvalidRequest(t *testing.T) {
	dir := t.TempDir()
	r := validRequest()
	r.ExternalID = "short"
	if _, err := Write(r, Options{Dir: dir}); err == nil {
		t.Fatal("Write accepted an invalid request")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a failed Write left %d files behind: %v", len(entries), entries)
	}
}

func TestWriteRequiresADirectory(t *testing.T) {
	_, err := Write(validRequest(), Options{})
	if err == nil {
		t.Fatal("Write with no directory succeeded")
	}
	if !strings.Contains(err.Error(), "--out") {
		t.Errorf("the error does not name the flag to pass: %v", err)
	}
}

// TestPlanTouchesNothing is the plan half of CLAUDE.md rule 5's plan/apply split.
func TestPlanTouchesNothing(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "not-yet")

	res, err := Plan(validRequest(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(res.Files) != renderersCount {
		t.Errorf("the plan lists %d files, want %d", len(res.Files), renderersCount)
	}
	for _, f := range res.Files {
		if f.Status != Created {
			t.Errorf("%s: plan says %s for a directory that does not exist", f.Name, f.Status)
		}
	}
	if _, lerr := os.Lstat(dir); !errors.Is(lerr, fs.ErrNotExist) {
		t.Error("Plan created the output directory")
	}

	// And against an existing bundle, the plan must match what Write then does.
	if _, werr := Write(validRequest(), Options{Dir: dir}); werr != nil {
		t.Fatalf("Write: %v", werr)
	}
	before := snapshot(t, dir)
	plan, err := Plan(validRequest(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, f := range plan.Files {
		if f.Status != Unchanged {
			t.Errorf("%s: plan says %s, want unchanged", f.Name, f.Status)
		}
	}
	if after := snapshot(t, dir); !equalSnapshots(before, after) {
		t.Error("Plan modified the bundle")
	}
}

// TestPlanReportsWhatWriteWouldRefuse: a plan that says "replaced" where Write
// would error is a plan nobody can act on.
func TestPlanReportsWhatWriteWouldRefuse(t *testing.T) {
	dir := t.TempDir()
	r := validRequest()
	if _, err := Write(r, Options{Dir: dir}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileREADME), []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Plan(r, Options{Dir: dir}); err == nil {
		t.Error("Plan did not report that the write would be refused")
	}
	plan, err := Plan(r, Options{Dir: dir, Force: true})
	if err != nil {
		t.Fatalf("Plan with force: %v", err)
	}
	var found bool
	for _, f := range plan.Files {
		if f.Name == FileREADME {
			found = true
			if f.Status != Replaced {
				t.Errorf("%s: plan says %s, want replaced", f.Name, f.Status)
			}
		}
	}
	if !found {
		t.Errorf("the plan does not mention %s", FileREADME)
	}
}

func TestResultStringNamesEveryFile(t *testing.T) {
	dir := t.TempDir()
	res, err := Write(validRequest(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := res.String()
	for _, name := range FileNames() {
		if !strings.Contains(out, name) {
			t.Errorf("the output does not mention %s:\n%s", name, out)
		}
	}
	if !strings.Contains(out, dir) {
		t.Errorf("the output does not say where it wrote:\n%s", out)
	}
	// The ExternalId is in the bundle, not in the terminal: an operator pasting
	// this into a ticket should not paste a credential-shaped value with it.
	if strings.Contains(out, testExternalID) {
		t.Error("the CLI output echoes the ExternalId")
	}
}

func TestStatusStringsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range []Status{Created, Unchanged, Replaced} {
		if seen[s.String()] {
			t.Errorf("two statuses render as %q", s.String())
		}
		seen[s.String()] = true
	}
	if got := Status(99).String(); got != "unknown" {
		t.Errorf("Status(99) = %q", got)
	}
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // test fixture path
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(data)
	}
	return out
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestARerunTightensAFileThatWasLoosened is the regression for the case where
// "unchanged" was actively reassuring.
//
// Write skipped the write entirely when contents matched, which also skipped the
// chmod — so a bundle whose mode was loosened by anything that does not preserve
// permissions (cp without -p, tar -x, a git checkout, chmod -R) stayed
// world-readable forever, and automat reported "unchanged" every time. The
// ExternalId sat readable by every account on the host while the tool said
// everything was fine.
//
// TestWrittenFilesAreOwnerOnly did not catch this because it only ever ran a first
// write, so it asserted a property the tool established once and never maintained.
// That is the shape worth remembering: a test that only covers the create path
// cannot speak to ensure semantics at all.
func TestARerunTightensAFileThatWasLoosened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode semantics")
	}
	dir := t.TempDir()
	if _, err := Write(validRequest(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	for _, name := range FileNames() {
		if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Byte-identical contents: the path that used to skip the chmod.
	res, err := Write(validRequest(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range FileNames() {
		fi, serr := os.Stat(filepath.Join(dir, name))
		if serr != nil {
			t.Fatal(serr)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %s after a re-run — it holds an ExternalId and the run "+
				"reported success", name, fi.Mode().Perm())
		}
	}
	// And it must say so. Repairing an operator's filesystem silently is its own
	// problem, and "unchanged" would be a false statement about what happened.
	// Only the files this test loosened; .gitignore was left alone and correctly
	// reports unchanged.
	loosened := map[string]bool{}
	for _, n := range FileNames() {
		loosened[n] = true
	}
	for _, f := range res.Files {
		if loosened[f.Name] && f.Status != Tightened {
			t.Errorf("%s reported %q, want %q: the mode was changed and the report must "+
				"say it was", f.Name, f.Status, Tightened)
		}
	}
}

// TestWriteRefusesAHardlinkedBundleFile: a hardlink passes every check a symlink
// fails. Lstat reports a regular file, the mode is whatever the link target's is, and
// os.Root has nothing to refuse because no path is escaped. Writing through it
// truncates the other name's contents and replaces them with a document containing
// the ExternalId — data destruction plus secret propagation, in one write.
func TestWriteRefusesAHardlinkedBundleFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hardlink semantics")
	}
	base := t.TempDir()
	victimDir := filepath.Join(base, "victim")
	if err := os.Mkdir(victimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(victimDir, "precious.txt")
	const precious = "something the operator cares about\n"
	if err := os.WriteFile(victim, []byte(precious), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "bundle")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, filepath.Join(out, FileRoleCFN)); err != nil {
		t.Fatal(err)
	}

	// --force, because that is the flag an operator reaches for when a write is
	// refused, and it must not be the one that causes the damage.
	_, err := Write(validRequest(), Options{Dir: out, Force: true})
	if err == nil {
		t.Fatal("Write wrote through a hardlinked bundle file")
	}
	if !strings.Contains(err.Error(), "hard link") {
		t.Errorf("the error does not name the cause: %v", err)
	}
	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != precious {
		t.Errorf("the linked file was overwritten:\ngot:  %q\nwant: %q", got, precious)
	}
	if strings.Contains(string(got), testExternalID) {
		t.Error("the ExternalId was copied into the linked file")
	}
}

// TestWriteRefusesAFIFOWithoutHanging. An existing bundle file is opened O_RDWR to
// compare it against what automat would render. Opening a FIFO waits for the other
// end to appear, so a mode-0600 pipe the operator owns — which passes every
// permission check — turned `automat setup` into a hang with no output and an
// ExternalId sitting in memory. The Lstat before the open refuses it, and
// safeio.OpenNonBlock covers one swapped in after that check.
//
// The timeout is the assertion. A test that only checked the error would hang rather
// than fail if the flag were dropped, which is how this class of bug survives.
func TestWriteRefusesAFIFOWithoutHanging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs")
	}
	out := t.TempDir()
	if err := mkfifo(filepath.Join(out, FileRoleCFN), 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Write(validRequest(), Options{Dir: out, Force: true})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was accepted as a bundle file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("the error does not name the cause: %v", err)
		}
		if strings.Contains(err.Error(), testExternalID) {
			t.Errorf("the refusal leaks the ExternalId: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Write blocked on a FIFO in the output directory — opening a pipe waits for " +
			"the other end, so this hangs with an ExternalId in memory and no output")
	}
}

// TestWriteRefusesAnInodeSwapBetweenTheCheckAndTheOpen covers the tie between the
// two resolutions in inspectForWrite: the Lstat that decides the entry is an
// ordinary regular file, and the open that actually gets written.
//
// os.Root does not close this. Verified against go1.24: it refuses a symlink whose
// target escapes the root but follows one whose target is inside it, and it silently
// ignores O_NOFOLLOW in the flags it is handed. So an attacker who can write the
// output directory can leave a regular file for the Lstat to approve and replace it
// with a link to another entry before the open — and the descriptor's own Stat then
// reports the target, a perfectly regular file. os.SameFile is what refuses it.
//
// Simulated by making the swap unconditional rather than racing for it: this asserts
// the check exists, and a race would assert only that this machine lost slowly.
func TestWriteRefusesAnInodeSwapBetweenTheCheckAndTheOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	out := t.TempDir()
	// A regular file at the bundle name, and a second file for it to become.
	if err := os.WriteFile(filepath.Join(out, FileRoleCFN), []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(out, "attacker-keeps-this")
	if err := os.WriteFile(other, []byte("attacker\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	// The Lstat inside inspectForWrite sees the regular file; the swap happens
	// before the open.
	fi, err := root.Lstat(FileRoleCFN)
	if err != nil {
		t.Fatal(err)
	}
	if rmErr := os.Remove(filepath.Join(out, FileRoleCFN)); rmErr != nil {
		t.Fatal(rmErr)
	}
	if lnErr := os.Symlink("attacker-keeps-this", filepath.Join(out, FileRoleCFN)); lnErr != nil {
		t.Fatal(lnErr)
	}

	f, err := root.OpenFile(FileRoleCFN, os.O_RDWR, fileMode)
	if err != nil {
		t.Fatalf("os.Root followed the in-root symlink and then failed to open it: %v", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Mode().IsRegular() {
		t.Fatal("the descriptor should report the symlink's target, a regular file — " +
			"if this fires, the premise of the check has changed")
	}
	if os.SameFile(fi, st) {
		t.Fatal("the swapped file compares equal to the one that was inspected, so the " +
			"SameFile tie in inspectForWrite cannot detect this")
	}
}

// TestAPartialBundleSaysItIsPartial: rendering happens before any write, so a bad
// request cannot leave a half-bundle — but a write failure partway through can, and
// the loop returns on the first error.
//
// The dangerous version of this is an operator rotating an ExternalId: the
// CloudFormation and Terraform templates end up requiring different values, both mode
// 0600, with nothing marking which is stale. Central IT applies one, and the other is
// wrong in a way that surfaces much later as an opaque AccessDenied. Worse, a plain
// re-run reports the stale files as "unchanged", so it never converges — which is why
// the error has to name --force.
func TestAPartialBundleSaysItIsPartial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode semantics")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the mode that makes this fail")
	}
	dir := t.TempDir()
	// A directory in place of a bundle file: refused, and it is not the first file
	// written, so earlier ones have already landed.
	names := FileNames()
	blocked := names[len(names)-1]
	if err := os.Mkdir(filepath.Join(dir, blocked), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Write(validRequest(), Options{Dir: dir, Force: true})
	if err == nil {
		t.Fatal("Write reported success with a bundle file blocked")
	}
	msg := err.Error()
	for _, want := range []string{"incomplete", blocked, "--force"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q, so the operator cannot tell what state "+
				"the directory is in or how to recover:\n%v", want, err)
		}
	}
}

// TestTheBundleIgnoresItselfInGit is F6's regression, and it is the finding with the
// worst recovery story: an operator who commits the ExternalId can only undo it by
// rewriting history, and on a public repository not even that.
//
// The generated README already said "do not commit this" — advice printed inside the
// file being committed. `automat setup --out ./bundle` inside a checkout is the
// obvious thing to do, and it was one `git add -A` away from publishing a credential.
func TestTheBundleIgnoresItselfInGit(t *testing.T) {
	dir := t.TempDir()
	if _, err := Write(validRequest(), Options{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, fileGitignore))
	if err != nil {
		t.Fatalf("the bundle has no %s: %v", fileGitignore, err)
	}
	// "*" and not a list of the five names: a list is a thing to forget to update,
	// and there is no file in this directory that belongs in version control.
	var ignoresEverything bool
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "*" {
			ignoresEverything = true
		}
	}
	if !ignoresEverything {
		t.Errorf("%s does not ignore everything, so a file added later is unprotected:\n%s",
			fileGitignore, data)
	}
	if !strings.Contains(string(data), "ExternalId") {
		t.Error("the file does not say why it is there, so an operator who finds it in the " +
			"way will delete it without knowing what it was for")
	}
	// It must be as unreadable as the secret it sits beside.
	fi, err := os.Stat(filepath.Join(dir, fileGitignore))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("%s is mode %s", fileGitignore, fi.Mode().Perm())
	}
}
