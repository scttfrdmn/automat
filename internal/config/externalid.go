// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/scttfrdmn/automat/internal/safeio"
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

// maxExternalIDFileBytes bounds the read. AWS's own ExternalId limit is 1224
// characters; the slack above it is for trailing whitespace an editor adds. A file
// larger than this is not an ExternalId — it is a log, a keyring database, or the
// wrong path — and reading it unbounded is a way to exhaust memory with a value the
// operator may have pointed somewhere by mistake.
const maxExternalIDFileBytes = 4096

// reResolvedExternalID is AWS's documented ExternalId charset and length, and it is
// deliberately *looser* than internal/bundle's reExternalID.
//
// The two validate different things. bundle generates a value and so may insist on
// its own narrow form. Here the value is being *consumed*, and it must equal
// whatever the deployed trust policy checks — which may predate automat, or come
// from a vendor who chose it. Refusing a `/` that AWS accepts would reject a
// working configuration for no security gain.
//
// What it does refuse is what has no business in a credential: control bytes, ANSI
// escapes, NUL padding, and anything long enough that AWS would reject it anyway.
// Without this, `"a"` resolves and is sent to AssumeRole as a confused-deputy
// defense, and a value carrying an escape sequence reaches a terminal.
//
// The length is checked in code rather than as a repeat count because RE2 caps a
// bounded repeat at 1000, below AWS's own limit.
var reResolvedExternalID = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/_-]+$`)

// maxExternalIDChars is AWS's documented ExternalId length limit.
const maxExternalIDChars = 1224

// minExternalIDChars is the point below which a value is short enough to guess.
// It matches the floor internal/bundle enforces on the values it generates.
const minExternalIDChars = 16

// validateResolvedExternalID checks the value that is about to be sent to
// AssumeRole. Its errors describe the shape and never echo the value.
func validateResolvedExternalID(v, source string) error {
	if !reResolvedExternalID.MatchString(v) || len(v) > maxExternalIDChars {
		return fmt.Errorf("the ExternalId from %s is not a value AWS accepts: it must be at most %d "+
			"characters of letters, digits, and _+=,.@:/- with no whitespace or control characters "+
			"(the value read was %d characters). automat has not sent it; check that %s contains only "+
			"the ExternalId", source, maxExternalIDChars, len(v), source)
	}
	// Short-but-valid is worth a distinct message: it is accepted by AWS and
	// useless as a defense, and an operator who typed a placeholder needs to be
	// told that rather than get an opaque AccessDenied from STS later.
	if len(v) < minExternalIDChars {
		return fmt.Errorf("the ExternalId from %s is only %d characters, which is short enough to "+
			"guess — and a guessable ExternalId is worse than none, because it looks like a control. "+
			"Generate one with `automat setup --request`, which produces 160 bits, and set the same "+
			"value in the trust policy", source, len(v))
	}
	return nil
}

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
		// Redacted like every other branch. "prod:LiveExternalIdValue..." reaches
		// here, and echoing the scheme alone still discloses the shape of what the
		// operator typed; there is nothing to gain by naming it.
		return fmt.Errorf("%s has no target — write env:VAR_NAME or file:/path", redactRef(ref))
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
		// The scheme is echoed but the target is not: a reference of
		// "prod:LiveExternalIdValue123456" is most likely a value with a prefix,
		// which is exactly the mistake this branch catches.
		return fmt.Errorf("unknown scheme %q in %s — automat understands env:VAR_NAME and "+
			"file:/path", scheme, redactRef(ref))
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
		// Validated on this branch too. env: is the default form and has no file
		// mode to check, which makes it the easier of the two to leave unguarded —
		// and an environment variable is set by whatever launched automat, so its
		// contents are no more trustworthy than a file's.
		if err := validateResolvedExternalID(v, "$"+rest); err != nil {
			return "", err
		}
		return v, nil

	case ExternalIDSchemeFile:
		path, err := expandHome(rest)
		if err != nil {
			return "", err
		}
		// safeio, not os.Stat followed by os.ReadFile. Those are two resolutions
		// of the same name, and whoever can write the containing directory decides
		// which file the second one lands on — which means they choose the
		// ExternalId, which means they choose the confused-deputy defense this
		// value exists to be. safeio checks the descriptor it actually read from,
		// refuses a symlink (os.Root follows one whose target is inside the
		// directory, and ignores O_NOFOLLOW), refuses a pipe without hanging on
		// it, and bounds the read.
		data, err := safeio.ReadSecret(path, maxExternalIDFileBytes)
		if err != nil {
			return "", fmt.Errorf("the ExternalId the vendor role requires is unavailable: %w", err)
		}
		v := strings.TrimSpace(string(data))
		if v == "" {
			return "", fmt.Errorf("ExternalId file %s is empty", path)
		}
		if err := validateResolvedExternalID(v, path); err != nil {
			return "", err
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
