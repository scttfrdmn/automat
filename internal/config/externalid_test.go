// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRefRejectsABareValue is the point of the whole reference scheme. An
// operator who pastes the ExternalId into the config file has converted a value
// whose only property is being unguessable into one that gets committed, shared,
// and attached to tickets — and a validator that accepted it "for convenience"
// would be the reason.
func TestRefRejectsABareValue(t *testing.T) {
	err := validateExternalIDRef("a-real-looking-external-id")
	if err == nil {
		t.Fatal("a bare ExternalId was accepted as a reference")
	}
	if !strings.Contains(err.Error(), "env:VAR_NAME") {
		t.Errorf("error should show the accepted forms: %v", err)
	}
}

// TestRejectedRefIsNotEchoed. The rejected string may *be* a live ExternalId —
// that is the case this validator exists to catch — so repeating it moves the
// value the operator was trying to keep out of a file into a terminal and a CI
// transcript, where it is more likely to be captured, not less.
func TestRejectedRefIsNotEchoed(t *testing.T) {
	const value = "unmistakable-external-id-value"
	err := validateExternalIDRef(value)
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(err.Error(), value) {
		t.Errorf("the rejection echoes the value it refused to let you store:\n%v", err)
	}

	// Also via the config path, which is where an operator will actually hit it.
	_, cerr := Decode([]byte("[context.a]\nexternal_id_ref = \""+value+"\"\n"), "test.toml")
	if cerr == nil {
		t.Fatal("Decode accepted a bare ExternalId")
	}
	if strings.Contains(cerr.Error(), value) {
		t.Errorf("the config error echoes the ExternalId:\n%v", cerr)
	}
}

func TestRefShapes(t *testing.T) {
	cases := []struct {
		ref     string
		wantErr bool
	}{
		{"env:AUTOMAT_EXTERNAL_ID", false},
		{"env:_leading_underscore", false},
		{"file:/etc/automat/external-id", false},
		{"file:~/.config/automat/external-id", false},
		{"env:has-a-hyphen", true},   // not a valid env var name
		{"env:1LEADING_DIGIT", true}, // not a valid env var name
		{"env:", true},
		{"file:", true},
		{"keychain:automat", true}, // not implemented; must not be silently ignored
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			err := validateExternalIDRef(tc.ref)
			if tc.wantErr && err == nil {
				t.Error("accepted")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("rejected: %v", err)
			}
		})
	}
}

func TestResolveFromEnv(t *testing.T) {
	const value = "resolved-value-that-is-long-enough"
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", value)
	got, err := ResolveExternalID("env:AUTOMAT_TEST_EXTERNAL_ID")
	if err != nil {
		t.Fatalf("ResolveExternalID: %v", err)
	}
	if got != value {
		t.Errorf("= %q", got)
	}

	t.Run("unset", func(t *testing.T) {
		_, err := ResolveExternalID("env:AUTOMAT_TEST_UNSET_EXTERNAL_ID")
		if err == nil {
			t.Fatal("an unset variable must be an error, not an empty ExternalId sent to AssumeRole")
		}
		if !strings.Contains(err.Error(), "AUTOMAT_TEST_UNSET_EXTERNAL_ID") {
			t.Errorf("error should name the variable: %v", err)
		}
	})
}

func TestResolveFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "external-id")
	// A trailing newline is what any editor writes; sending it to AssumeRole
	// would fail the trust-policy comparison for a reason nobody would guess.
	if err := os.WriteFile(path, []byte("resolved-value-that-is-long-enough\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ResolveExternalID("file:" + path)
	if err != nil {
		t.Fatalf("ResolveExternalID: %v", err)
	}
	if got != "resolved-value-that-is-long-enough" {
		t.Errorf("= %q, want the value with surrounding whitespace trimmed", got)
	}
}

// TestResolveRefusesALooseMode. A warning about a value whose only job is to be
// unguessable is advice nobody acts on, and the fix is one chmod. Refusing is the
// only setting that changes an outcome.
func TestResolveRefusesALooseMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "external-id")
			if err := os.WriteFile(path, []byte("value-long-enough-to-pass-the-floor"), mode); err != nil {
				t.Fatalf("write: %v", err)
			}
			// WriteFile applies the umask, so set the mode explicitly.
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			_, err := ResolveExternalID("file:" + path)
			if err == nil {
				t.Fatalf("read an ExternalId from a mode %#o file", mode)
			}
			if !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("error should give the one command that fixes it: %v", err)
			}
		})
	}
}

// TestResolveRefusesAValueThatIsNotAnExternalID. Every check in this file used to
// be about the *file*: its mode, its existence, whether it was empty. Nothing
// looked at what came out of it. So "a" resolved successfully and went to
// AssumeRole as the confused-deputy defense, and a value carrying an ANSI escape
// went wherever the caller printed it.
//
// Both schemes are covered. env: has no mode to check and is the easier one to
// forget, which is exactly why it is in the table.
func TestResolveRefusesAValueThatIsNotAnExternalID(t *testing.T) {
	const good = "automat-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cases := []struct {
		name  string
		value string
		want  string // substring the error must contain
	}{
		{"a single character", "a", "short enough to guess"},
		{"a short placeholder", "changeme", "short enough to guess"},
		// NUL is file-only: setenv refuses it, so the env subtest skips it.
		{"NUL padding", good + "\x00\x00", "AWS accepts"},
		{"an ANSI escape", good + "\x1b[2K", "AWS accepts"},
		{"an interior newline", "first-line-value\nsecond-line", "AWS accepts"},
		{"an interior space", "value with spaces in it", "AWS accepts"},
		{"a tab", good + "\tmore", "AWS accepts"},
		{"over AWS's length limit", strings.Repeat("a", maxExternalIDChars+1), "AWS accepts"},
		{"a shell metacharacter", good + ";rm -rf /", "AWS accepts"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/env", func(t *testing.T) {
			if strings.ContainsRune(tc.value, 0) {
				t.Skip("an environment variable cannot contain NUL; covered by the file subtest")
			}
			t.Setenv("AUTOMAT_TEST_BAD_EXTERNAL_ID", tc.value)
			_, err := ResolveExternalID("env:AUTOMAT_TEST_BAD_EXTERNAL_ID")
			if err == nil {
				t.Fatalf("resolved %q and would have sent it to AssumeRole", tc.value)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should explain the shape (%q): %v", tc.want, err)
			}
			assertNoRawValue(t, err, tc.value)
		})
		t.Run(tc.name+"/file", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "external-id")
			if err := os.WriteFile(path, []byte(tc.value), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			_, err := ResolveExternalID("file:" + path)
			if err == nil {
				t.Fatalf("resolved %q from a file and would have sent it to AssumeRole", tc.value)
			}
			assertNoRawValue(t, err, tc.value)
		})
	}

	t.Run("a real one is still accepted", func(t *testing.T) {
		t.Setenv("AUTOMAT_TEST_GOOD_EXTERNAL_ID", good)
		got, err := ResolveExternalID("env:AUTOMAT_TEST_GOOD_EXTERNAL_ID")
		if err != nil {
			t.Fatalf("a generated-shape ExternalId was refused: %v", err)
		}
		if got != good {
			t.Errorf("= %q", got)
		}
	})

	// AWS permits `/` and automat's own generator does not. The resolver must not
	// reject a working configuration whose value came from somewhere else.
	t.Run("AWS-valid characters automat does not generate", func(t *testing.T) {
		for _, v := range []string{
			"vendor/tenant/0123456789abcdef",
			"acct:1234567890:external-id",
			"a+b=c,d.e@f-g_h/ijklmnopqrst",
		} {
			t.Setenv("AUTOMAT_TEST_ODD_EXTERNAL_ID", v)
			if _, err := ResolveExternalID("env:AUTOMAT_TEST_ODD_EXTERNAL_ID"); err != nil {
				t.Errorf("%q is valid to AWS and must resolve: %v", v, err)
			}
		}
	})
}

// assertNoRawValue is the rule for every error in this file: the value may be a
// live ExternalId, so a rejection must not move it into a terminal or a CI log.
// Short values are exempt from the check itself — "a" appears in ordinary prose —
// but the long ones are the ones that matter.
func assertNoRawValue(t *testing.T, err error, value string) {
	t.Helper()
	if len(value) < 8 {
		return
	}
	if strings.Contains(err.Error(), value) {
		t.Errorf("the rejection echoes the value it refused:\n%v", err)
	}
	for _, bad := range []string{"\x1b", "\x00", "\n\t"} {
		if strings.Contains(value, bad) && strings.Contains(err.Error(), bad) {
			t.Errorf("the rejection passed through %q from the value:\n%q", bad, err.Error())
		}
	}
}

// TestResolveRefusesASymlinkedExternalIDFile and the mode/pipe cases live in
// internal/safeio, which owns those checks. This test asserts only that the
// resolver routes through it — a future refactor that went back to os.ReadFile
// would pass every other test in this file.
func TestResolveGoesThroughTheGuardedReader(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("automat-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "external-id")
	if err := os.Symlink("real", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, err := ResolveExternalID("file:" + link)
	if err == nil {
		t.Fatal("resolved an ExternalId through a symlink; the resolver is not using safeio")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveFileErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("absent", func(t *testing.T) {
		_, err := ResolveExternalID("file:" + filepath.Join(dir, "nope"))
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("the remediation should say how to create it safely: %v", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		path := filepath.Join(dir, "empty")
		if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := ResolveExternalID("file:" + path); err == nil {
			t.Fatal("a whitespace-only file must not resolve to an empty ExternalId")
		}
	})
}
