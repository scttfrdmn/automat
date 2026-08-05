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
)

func TestWriteProducesTheWholeBundle(t *testing.T) {
	dir := t.TempDir()
	res, err := Write(validRequest(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(res.Files) != renderersCount {
		t.Fatalf("wrote %d files, want %d", len(res.Files), renderersCount)
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
	if len(entries) != renderersCount {
		t.Errorf("%d entries in the directory, want %d", len(entries), renderersCount)
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
	if !strings.Contains(res.Dir, "narrowed") {
		t.Errorf("the result does not mention narrowing the permissions: %q", res.Dir)
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

// TestWriteEscapesNothingThroughASymlinkedOutputDirectory covers the other half of
// the os.Root argument: the --out path itself may be a symlink, which is fine —
// the operator named it — but everything inside must resolve within the resolved
// directory, not through further links.
func TestWriteEscapesNothingThroughASymlinkedOutputDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	res, err := Write(validRequest(), Options{Dir: link})
	if err != nil {
		t.Fatalf("Write into a symlinked directory: %v", err)
	}
	// The files land in the real directory, and the result reports the path the
	// operator gave — resolving it silently would be a different kind of lie.
	for _, name := range FileNames() {
		if _, err := os.Stat(filepath.Join(real, name)); err != nil {
			t.Errorf("%s did not land in the target directory: %v", name, err)
		}
	}
	if res.Dir == "" {
		t.Error("the result does not report where it wrote")
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
