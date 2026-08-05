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
	t.Setenv("AUTOMAT_TEST_EXTERNAL_ID", "resolved-value")
	got, err := ResolveExternalID("env:AUTOMAT_TEST_EXTERNAL_ID")
	if err != nil {
		t.Fatalf("ResolveExternalID: %v", err)
	}
	if got != "resolved-value" {
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
	if err := os.WriteFile(path, []byte("resolved-value\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ResolveExternalID("file:" + path)
	if err != nil {
		t.Fatalf("ResolveExternalID: %v", err)
	}
	if got != "resolved-value" {
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
			if err := os.WriteFile(path, []byte("value"), mode); err != nil {
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
