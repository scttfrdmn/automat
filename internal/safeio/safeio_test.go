// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const secret = "an-unmistakable-secret-value"

// tightDir returns a temp dir at 0700. t.TempDir is 0700 already on the platforms
// this runs on, but the mode is load-bearing for these tests, so it is set rather
// than assumed.
func tightDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	return dir
}

// fataler is the slice of *testing.T that writeSecret needs. It exists so the
// same helper can be called from the swap goroutine below, where Fatalf is not
// allowed, and from a table setup where the following assertion reports failure.
type fataler interface {
	Helper()
	Fatalf(string, ...any)
}

func writeSecret(t fataler, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(secret+"\n"), mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	// WriteFile applies the umask, so set the mode explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
}

func TestReadSecretReadsAnOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(tightDir(t), "external-id")
	writeSecret(t, path, 0o600)
	got, err := ReadSecret(path, 4096)
	if err != nil {
		t.Fatalf("ReadSecret: %v", err)
	}
	if strings.TrimSpace(string(got)) != secret {
		t.Errorf("= %q", got)
	}
}

// TestReadSecretRefusesASymlink is the finding os.Root does not cover. Verified
// against go1.24: os.Root follows a symlink whose target is inside the root, and
// it *ignores* syscall.O_NOFOLLOW in OpenFile's flags. So the refusal has to be
// explicit, and a test that only planted an escaping symlink would pass without it.
func TestReadSecretRefusesASymlink(t *testing.T) {
	dir := tightDir(t)
	attacker := filepath.Join(dir, "attackers-value")
	writeSecret(t, attacker, 0o600)

	link := filepath.Join(dir, "external-id")
	if err := os.Symlink("attackers-value", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	_, err := ReadSecret(link, 4096)
	if err == nil {
		t.Fatal("read a secret through a symlink to a file inside the same directory")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error should say what it refused: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal echoes the secret: %v", err)
	}
}

// TestReadSecretRefusesAFIFOWithoutHanging covers both halves of the FIFO problem:
// a pipe is not a file a secret comes from, and opening one for reading with no
// writer blocks forever (verified: still blocked after two seconds).
//
// Jam-checked, and the result is worth recording. Two defenses cover the FIFO
// planted *before* the check — the Lstat refusal and O_NONBLOCK — so removing
// either one alone still passes this test; removing both hangs, and the timeout
// below is what catches it. The residual case O_NONBLOCK alone covers is a FIFO
// swapped in between the Lstat and the open, which no test can win reliably. So
// this test does not prove the flag is present. It proves the pair is.
func TestReadSecretRefusesAFIFOWithoutHanging(t *testing.T) {
	dir := tightDir(t)
	path := filepath.Join(dir, "external-id")
	if err := mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ReadSecret(path, 4096)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO resolved as an ExternalId")
		}
		if !strings.Contains(err.Error(), "regular file") {
			t.Errorf("error should say a secret comes from a file: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadSecret blocked on a FIFO with no writer — a mode-0600 pipe the operator " +
			"owns is a denial of service that looks like a network stall")
	}
}

func TestReadSecretRefusesALooseMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666, 0o601, 0o610} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(tightDir(t), "external-id")
			writeSecret(t, path, mode)
			_, err := ReadSecret(path, 4096)
			if err == nil {
				t.Fatalf("read a secret from a mode %#o file", mode)
			}
			if !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("error should give the one command that fixes it: %v", err)
			}
		})
	}
}

// TestReadSecretRefusesAWorldWritableDirectory. A 0600 file in a 0777 directory is
// not protected by its own mode: anyone who can write the directory can replace the
// file with one of theirs, at any mode they like. The file's mode describes the
// file, not who gets to decide what the file is.
func TestReadSecretRefusesAWorldWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "external-id")
	writeSecret(t, path, 0o600)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	_, err := ReadSecret(path, 4096)
	if err == nil {
		t.Fatal("read a secret from a 0600 file in a 0777 directory")
	}
	if !strings.Contains(err.Error(), "chmod 700") {
		t.Errorf("error should name the directory fix: %v", err)
	}
}

// TestReadSecretAllowsAStickyDirectory. /tmp is 1777 on every unix, and the sticky
// bit is what makes that safe: one user cannot delete or rename another's entry.
// Refusing sticky directories would reject the most common location for a
// throwaway ExternalId file and teach the operator to work around the check.
func TestReadSecretAllowsAStickyDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "external-id")
	writeSecret(t, path, 0o600)
	// Sticky is a high bit in Go's FileMode, not octal 0o1000: os.Chmod(dir, 0o1777)
	// sets a plain 0777 directory, which this check refuses and should.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Skipf("cannot set sticky: %v", err)
	}
	if _, err := ReadSecret(path, 4096); err != nil {
		t.Errorf("a sticky world-writable directory is the /tmp case and must be allowed: %v", err)
	}
}

func TestReadSecretRefusesADirectory(t *testing.T) {
	dir := tightDir(t)
	sub := filepath.Join(dir, "external-id")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := ReadSecret(sub, 4096); err == nil {
		t.Fatal("a directory resolved as an ExternalId")
	}
}

// TestReadSecretBoundsTheRead. An unbounded read of a path the operator may have
// pointed at the wrong thing — a log, a keyring database, /dev/zero on a platform
// where that is a regular file — is a way to exhaust memory. The boundary is
// stated as an error rather than a truncation, because a truncated secret fails
// authentication for a reason nobody would guess from the message AWS returns.
func TestReadSecretBoundsTheRead(t *testing.T) {
	dir := tightDir(t)
	path := filepath.Join(dir, "external-id")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 5000)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ReadSecret(path, 4096)
	if err == nil {
		t.Fatal("read 5000 bytes under a 4096-byte limit")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error should say the file is too large, not truncate silently: %v", err)
	}

	t.Run("exactly at the limit is fine", func(t *testing.T) {
		p := filepath.Join(tightDir(t), "external-id")
		if err := os.WriteFile(p, []byte(strings.Repeat("x", 4096)), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := ReadSecret(p, 4096)
		if err != nil {
			t.Fatalf("a file exactly at the limit must be accepted: %v", err)
		}
		if len(got) != 4096 {
			t.Errorf("len = %d, want 4096", len(got))
		}
	})
}

// TestCheckOpenSecretRefusesAnInodeSwap states the identity check directly, because
// winning the race from a test is inherently flaky. os.Root resolves the directory
// once, so the reachable window is small — but "small" is not "closed", and the
// consequence of losing is that an attacker chooses the ExternalId, which means
// they choose the confused-deputy defense.
func TestCheckOpenSecretRefusesAnInodeSwap(t *testing.T) {
	dir := tightDir(t)
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	writeSecret(t, a, 0o600)
	writeSecret(t, b, 0o600)

	ai, err := os.Lstat(a)
	if err != nil {
		t.Fatalf("lstat a: %v", err)
	}
	bi, err := os.Lstat(b)
	if err != nil {
		t.Fatalf("lstat b: %v", err)
	}

	// Same file: accepted.
	if sameErr := checkOpenSecret(a, ai, ai); sameErr != nil {
		t.Errorf("the same file was refused: %v", sameErr)
	}
	// Checked one file, opened another: refused.
	err = checkOpenSecret(a, ai, bi)
	if err == nil {
		t.Fatal("checked one inode and opened another without complaint")
	}
	if !strings.Contains(err.Error(), "changed while") {
		t.Errorf("error should say the file changed under it: %v", err)
	}
	if !strings.Contains(err.Error(), "Nothing was read") {
		t.Errorf("error should say no value was used: %v", err)
	}
}

// TestReadSecretUnderConcurrentSwapNeverReturnsTheAttackersValue is the race the
// audit demonstrated, run against the fix. It does not assert a win rate: it
// asserts that *every* successful read returned the owner's value. A read that
// errors is a fine outcome; a read that returns the attacker's bytes is not.
func TestReadSecretUnderConcurrentSwapNeverReturnsTheAttackersValue(t *testing.T) {
	dir := tightDir(t)
	path := filepath.Join(dir, "external-id")
	writeSecret(t, path, 0o600)

	const attackerValue = "attacker-chose-this-external-id"
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(attackerValue+"\n"), 0o644); err != nil {
		t.Fatalf("write loose: %v", err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatalf("chmod loose: %v", err)
	}

	// The owner's file is moved aside rather than rewritten. An earlier version of
	// this test recreated it with WriteFile each round, which truncates -- so it
	// read a legitimately empty file the owner had just created and reported it as
	// an attacker value. Two pre-made files ping-ponging through one name with
	// atomic renames leaves no window that is not genuinely one of the two.
	own := filepath.Join(dir, "own")
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			switch i % 4 {
			case 0:
				_ = os.Rename(path, own) // owner's file out
			case 1:
				_ = os.Rename(loose, path) // attacker's file in
			case 2:
				_ = os.Rename(path, loose) // attacker's file out
			case 3:
				_ = os.Rename(own, path) // owner's file back
			}
		}
	}()

	var reads, refused int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := ReadSecret(path, 4096)
		if err != nil {
			refused++
			continue
		}
		reads++
		if v := strings.TrimSpace(string(got)); v != secret {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("ReadSecret returned a value that is not the owner's: %q "+
				"(the attacker planted %q)", v, attackerValue)
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d reads returned the owner's value, %d refused", reads, refused)
	if reads == 0 && refused == 0 {
		t.Fatal("the race loop never ran; the test proved nothing")
	}
}

// quietT drops setup failures. Used from the swapping goroutine, which is allowed
// to lose races with itself, and from table setups where the assertion that
// follows reports the real failure.
type quietT struct{}

func (quietT) Fatalf(string, ...any) {}
func (quietT) Helper()               {}

func TestReadSecretRefusesAFileOwnedBySomeoneElse(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to create a file owned by another uid")
	}
	dir := tightDir(t)
	path := filepath.Join(dir, "external-id")
	writeSecret(t, path, 0o600)
	if err := os.Chown(path, 12345, 12345); err != nil {
		t.Skipf("chown: %v", err)
	}
	_, err := ReadSecret(path, 4096)
	if err == nil {
		t.Fatal("read a secret from a file owned by another account")
	}
	if !strings.Contains(err.Error(), "chown") {
		t.Errorf("error should name the fix: %v", err)
	}
}

func TestReadSecretOnAMissingFileSaysHowToCreateItSafely(t *testing.T) {
	_, err := ReadSecret(filepath.Join(tightDir(t), "nope"), 4096)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("remediation should say how to create it safely: %v", err)
	}
}

func TestEnsureDirCreatesAndReuses(t *testing.T) {
	base := tightDir(t)
	dir := filepath.Join(base, "nested", "bundle")

	root, err := EnsureDir(dir, SecretDirMode)
	if err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if cerr := root.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !fi.IsDir() {
		t.Fatal("not a directory")
	}

	// Idempotent: a second call reuses it (CLAUDE.md rule 4).
	root2, err := EnsureDir(dir, SecretDirMode)
	if err != nil {
		t.Fatalf("second EnsureDir: %v", err)
	}
	_ = root2.Close()
}

// TestEnsureDirRefusesASymlinkedDirectory. The files written into this directory
// contain a live ExternalId, so a symlink standing where the directory belongs
// chooses where that secret lands.
func TestEnsureDirRefusesASymlinkedDirectory(t *testing.T) {
	base := tightDir(t)
	real := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "bundle")
	if err := os.Symlink("elsewhere", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	_, err := EnsureDir(link, SecretDirMode)
	if err == nil {
		t.Fatal("wrote a bundle through a symlinked output directory")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error should say what it refused: %v", err)
	}
}

// TestEnsureDirFollowsSymlinksAboveTheDirectory is the case that must not
// regress. On darwin /tmp is itself a symlink to /private/tmp, so refusing every
// symlink in the path would refuse every temp directory — and an operator who
// names a path through a symlinked parent is naming a real location. Only the
// final component, the one files land in, is checked.
func TestEnsureDirFollowsSymlinksAboveTheDirectory(t *testing.T) {
	base := tightDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "via")
	if err := os.Symlink("real", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	root, err := EnsureDir(filepath.Join(link, "bundle"), SecretDirMode)
	if err != nil {
		t.Fatalf("a symlinked parent must be allowed: %v", err)
	}
	_ = root.Close()
	if _, err := os.Stat(filepath.Join(real, "bundle")); err != nil {
		t.Errorf("the directory did not land through the symlinked parent: %v", err)
	}
}

func TestEnsureDirRefusesAFileWhereTheDirectoryBelongs(t *testing.T) {
	base := tightDir(t)
	path := filepath.Join(base, "bundle")
	writeSecret(t, path, 0o600)
	_, err := EnsureDir(path, SecretDirMode)
	if err == nil {
		t.Fatal("EnsureDir accepted a regular file as the output directory")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error should say what is there: %v", err)
	}
}

// TestErrorsNeverEchoTheSecret sweeps every refusal path. The value in this file is
// the thing automat exists to keep out of terminals, tickets, and CI transcripts,
// so no error may quote it — including the ones that had to read bytes to decide.
func TestErrorsNeverEchoTheSecret(t *testing.T) {
	mk := func(t *testing.T, f func(dir, path string)) error {
		dir := tightDir(t)
		path := filepath.Join(dir, "external-id")
		f(dir, path)
		_, err := ReadSecret(path, 4096)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		return err
	}
	cases := map[string]func(dir, path string){
		"loose mode": func(_, p string) { writeSecret(quietT{}, p, 0o644) },
		"loose dir":  func(d, p string) { writeSecret(quietT{}, p, 0o600); _ = os.Chmod(d, 0o777) },
		"too large":  func(_, p string) { _ = os.WriteFile(p, []byte(strings.Repeat(secret, 500)), 0o600) },
		"symlink":    func(d, p string) { writeSecret(quietT{}, filepath.Join(d, "t"), 0o600); _ = os.Symlink("t", p) },
		"directory":  func(_, p string) { _ = os.Mkdir(p, 0o700) },
		"missing":    func(_, _ string) {},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			err := mk(t, setup)
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the refusal echoes the secret:\n%v", err)
			}
		})
	}
}

// TestQuoteTargetCannotForgeOutput. A symlink target is attacker-chosen in exactly
// the case its error is printed, so it must not be able to emit an escape sequence
// or a newline into automat's own output. AUDIT-0's M1 class.
func TestQuoteTargetCannotForgeOutput(t *testing.T) {
	for _, target := range []string{
		"/tmp/x\x1b[1A\x1b[2K  created   delegation-policy.json",
		"/tmp/x\nrefused: nothing\n",
		"/tmp/x\rall good",
		strings.Repeat("/aaaa", 100),
	} {
		got := quoteTarget(target)
		for _, bad := range []string{"\x1b", "\n", "\r"} {
			if strings.Contains(got, bad) {
				t.Errorf("quoteTarget(%q) passed through %q: %s", target, bad, got)
			}
		}
	}
	if got := quoteTarget(""); !strings.Contains(got, "unreadable") {
		t.Errorf("an unreadable target should say so, got %s", got)
	}
}

func TestLinkCountAndOwnerAgreeWithTheFilesystem(t *testing.T) {
	dir := tightDir(t)
	path := filepath.Join(dir, "f")
	writeSecret(t, path, 0o600)
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if n, ok := LinkCount(fi); ok && n != 1 {
		t.Errorf("LinkCount = %d on a fresh file, want 1", n)
	}
	if uid, ok := OwnerUID(fi); ok && uid != uint32(os.Getuid()) {
		t.Errorf("OwnerUID = %d, want %d", uid, os.Getuid())
	}

	if lnErr := os.Link(path, filepath.Join(dir, "g")); lnErr != nil {
		t.Skipf("hardlink unsupported: %v", lnErr)
	}
	fi2, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if n, ok := LinkCount(fi2); ok && n != 2 {
		t.Errorf("LinkCount = %d after a hardlink, want 2", n)
	}
}

// Guard against the fs.ErrNotExist wrapping being dropped: the caller's message
// for a missing file is materially different from every other failure, and an
// errors.Is that stopped matching would silently downgrade it.
func TestMissingFileIsDistinguishable(t *testing.T) {
	_, _, err := OpenSecret(filepath.Join(tightDir(t), "absent"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, os.ErrPermission) {
		t.Errorf("a missing file reported as a permission problem: %v", err)
	}
	if !strings.Contains(err.Error(), "no file at") {
		t.Errorf("unexpected message: %v", err)
	}
}
