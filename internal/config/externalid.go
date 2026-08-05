// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ExternalId handling.
//
// The ExternalId defends the vendor role against the confused-deputy problem: it
// is the shared value that proves the caller of sts:AssumeRole is the account
// central IT meant to trust, not a third party that learned the role ARN. Its
// threat model is narrow and worth stating precisely, because the narrowness is
// what determines how it should be stored:
//
//   - It defends against someone who knows the role ARN but was never told the
//     ExternalId.
//   - It does NOT defend against anyone who can read the operator's disk, their
//     shell history, their CI logs, or the config file they attached to a ticket.
//
// So automat does not store it. The config file holds a *reference* to where the
// value comes from, and the value is fetched at assume time and never written
// anywhere. That keeps the config file safe to commit and safe to paste into the
// onboarding request central IT reviews — which matters, because the onboarding
// bundle is meant to be shared.

// The accepted reference forms.
const (
	// ExternalIDSchemeEnv reads the value from an environment variable:
	// "env:AUTOMAT_EXTERNAL_ID".
	ExternalIDSchemeEnv = "env"
	// ExternalIDSchemeFile reads it from a file, trimming trailing whitespace:
	// "file:~/.config/automat/external-id". The file must not be group- or
	// world-readable.
	ExternalIDSchemeFile = "file"
)

var reEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateExternalIDRef checks the reference's shape without resolving it.
//
// Notably it rejects a bare value. An operator who writes the ExternalId
// directly into the config file has silently converted a shared-secret-ish value
// into a committed one, and a validator that accepted it "for convenience" would
// be the reason that happens.
func validateExternalIDRef(ref string) error {
	scheme, rest, ok := strings.Cut(ref, ":")
	if !ok {
		return fmt.Errorf("%q is not a reference — write env:VAR_NAME or file:/path, not the value "+
			"itself; automat resolves the ExternalId at assume time and never stores it, so that a "+
			"config file stays safe to commit and to attach to a ticket", redactRef(ref))
	}
	if rest == "" {
		return fmt.Errorf("scheme %q has no target — write env:VAR_NAME or file:/path", scheme)
	}
	switch scheme {
	case ExternalIDSchemeEnv:
		if !reEnvName.MatchString(rest) {
			return fmt.Errorf("%q is not an environment variable name", rest)
		}
		return nil
	case ExternalIDSchemeFile:
		return nil
	default:
		return fmt.Errorf("unknown scheme %q — automat understands env:VAR_NAME and file:/path", scheme)
	}
}

// redactRef renders a rejected reference without echoing what may be a live
// ExternalId into a terminal, a log, or a CI transcript. The operator already
// knows what they typed; a validator that repeats it has moved a value they were
// trying to keep out of the config file into somewhere it is even more likely to
// be captured.
func redactRef(ref string) string {
	if len(ref) <= 4 {
		return strings.Repeat("*", len(ref))
	}
	return ref[:2] + strings.Repeat("*", len(ref)-2)
}

// ResolveExternalID fetches the ExternalId named by the reference.
//
// The returned value is a live credential-adjacent secret: pass it to AssumeRole
// and drop it. Never log it, never write it to an evidence manifest, never
// include it in an error message.
func ResolveExternalID(ref string) (string, error) {
	if err := validateExternalIDRef(ref); err != nil {
		return "", err
	}
	scheme, rest, _ := strings.Cut(ref, ":")
	switch scheme {
	case ExternalIDSchemeEnv:
		v := os.Getenv(rest)
		if v == "" {
			return "", fmt.Errorf("environment variable %s is unset or empty, so the ExternalId the "+
				"vendor role requires is unavailable — export it in this shell, or point "+
				"external_id_ref at a file", rest)
		}
		return v, nil

	case ExternalIDSchemeFile:
		path, err := expandHome(rest)
		if err != nil {
			return "", err
		}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("no ExternalId file at %s — create it containing only the value, "+
				"readable by you alone (chmod 600)", path)
		}
		if err != nil {
			return "", fmt.Errorf("stat ExternalId file %s: %w", path, err)
		}
		// Refusing a loose mode rather than warning about it: a warning on a
		// value whose only job is to be unguessable is advice nobody acts on,
		// and the fix is one chmod.
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return "", fmt.Errorf("ExternalId file %s is mode %#o, readable beyond its owner — "+
				"run: chmod 600 %s", path, perm, path)
		}
		data, err := os.ReadFile(path) //nolint:gosec // the operator's own referenced path
		if err != nil {
			return "", fmt.Errorf("read ExternalId file %s: %w", path, err)
		}
		v := strings.TrimSpace(string(data))
		if v == "" {
			return "", fmt.Errorf("ExternalId file %s is empty", path)
		}
		return v, nil
	}
	// Unreachable: validateExternalIDRef admits only the two schemes.
	return "", fmt.Errorf("unknown ExternalId reference scheme %q", scheme)
}

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand %s: %w", path, err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}
