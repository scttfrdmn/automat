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

// ExternalIDCharset is AWS's documented ExternalId charset, as a bare character
// class with no anchors or repeat.
//
// Exported as a string rather than kept as a compiled pattern because the role
// templates in internal/bundle need the same charset in *their* dialects — a
// CloudFormation `AllowedPattern` and a Terraform `regex()` call. It is one constant
// with two consumers instead of three copies that agree today.
//
// This package owns the definition because this package is where the value is
// *consumed*: whatever the deployed trust policy checks is what automat must later
// send to AssumeRole. The templates constrain a deploy-time input, so their bounds
// are a consuming constraint too, and they must be these. A template that accepted
// what ResolveExternalID later refuses would deploy a working role automat cannot
// use; a template narrower than AWS would refuse a trust policy that predates
// automat, or one whose value central IT chose before ever hearing of this tool.
const ExternalIDCharset = `[A-Za-z0-9+=,.@:/_-]`

// reResolvedExternalID anchors ExternalIDCharset over the whole value.
//
// It refuses what has no business in a credential: control bytes, ANSI escapes, NUL
// padding, whitespace, and anything long enough that AWS would reject it anyway.
// Without it, `"a"` resolves and is sent to AssumeRole as a confused-deputy defense,
// and a value carrying an escape sequence reaches a terminal.
//
// The length is checked in code rather than as a repeat count because RE2 caps a
// bounded repeat at 1000, below AWS's own limit.
var reResolvedExternalID = regexp.MustCompile(`^` + ExternalIDCharset + `+$`)

// MaxExternalIDChars is AWS's documented ExternalId length limit.
const MaxExternalIDChars = 1224

// MinExternalIDChars is the point below which a value is short enough to guess.
// AWS itself permits two characters; a two-character shared secret is a condition
// that reviews as a control and is not one.
const MinExternalIDChars = 16

// validateResolvedExternalID checks the value that is about to be sent to
// AssumeRole. Its errors describe the shape and never echo the value.
func validateResolvedExternalID(v, source string) error {
	if !reResolvedExternalID.MatchString(v) || len(v) > MaxExternalIDChars {
		return fmt.Errorf("the ExternalId from %s is not a value AWS accepts: it must be at most %d "+
			"characters of letters, digits, and _+=,.@:/- with no whitespace or control characters "+
			"(the value read was %d characters). automat has not sent it; check that %s contains only "+
			"the ExternalId", source, MaxExternalIDChars, len(v), source)
	}
	// Short-but-valid is worth a distinct message: it is accepted by AWS and
	// useless as a defense, and an operator who typed a placeholder needs to be
	// told that rather than get an opaque AccessDenied from STS later.
	if len(v) < MinExternalIDChars {
		return fmt.Errorf("the ExternalId from %s is only %d characters, which is short enough to "+
			"guess — and a guessable ExternalId is worse than none, because it looks like a control. "+
			"Generate %d bytes of randomness (`openssl rand -hex 24`) and set the same value in the "+
			"role's trust policy", source, len(v), MinExternalIDChars)
	}
	// Length and charset are satisfied and the value is still not a secret:
	// "0000000000000000" and "password12345678" both passed until this check. An
	// ExternalId's only property is being unguessable, so a placeholder is worse than
	// no condition at all — it puts a StringEquals in the trust policy that reviews as
	// a control and is not one.
	//
	// This check lives on the consuming side because that is now the only side there
	// is: automat does not choose this value and never sees it until it resolves one.
	// The reason is reported, the value is not.
	if reason, weak := weakExternalID(v); weak {
		return fmt.Errorf("the ExternalId from %s is not usable because %s. An ExternalId's only job "+
			"is to be a value a third party who knows the role ARN was never told, so a guessable one "+
			"leaves the condition in the trust policy looking like a control while being none. automat "+
			"has not sent it; replace the value in both %s and the role's trust policy", source, reason, source)
	}
	return nil
}

// weakExternalID reports whether v is degenerate enough that it is not a secret in
// any sense, and a short reason if so.
//
// Deliberately a small, closed list rather than a strength heuristic. An ExternalId
// that passes this is not thereby unguessable — nothing automat can compute would
// tell it that — so the check only catches the cases where a human has clearly typed
// a placeholder: one repeated character, a digit run, or a password-list staple.
// Anything cleverer would be a strength meter, and a strength meter that says "ok" is
// a claim automat cannot support. That is why nothing in automat's output ever tells
// an operator their ExternalId was judged strong.
//
// It lived in internal/bundle when automat generated this value and validated its own
// output. It now guards the only side that exists: automat receives a value chosen by
// whoever deployed the role, and "the requester typed `changeme`" became "somebody
// typed `changeme`" without becoming any less likely.
func weakExternalID(v string) (string, bool) {
	if v == "" {
		return "", false // The length check reports this one.
	}
	// A single character repeated: "aaaa...", "0000...".
	allSame := true
	for i := 1; i < len(v); i++ {
		if v[i] != v[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return "it is one character repeated", true
	}
	// All digits: a date, an account number, a counter.
	allDigits := true
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "it is all digits, so it is a number someone can count to", true
	}
	// A sequential run, ascending or descending, in either case: "123456...",
	// "abcdef...". Checked over the whole string rather than as a substring, so an
	// ExternalId that merely contains "abc" is unaffected.
	seq, rev := true, true
	lower := strings.ToLower(v)
	for i := 1; i < len(lower); i++ {
		if lower[i] != lower[i-1]+1 {
			seq = false
		}
		if lower[i] != lower[i-1]-1 {
			rev = false
		}
	}
	if seq || rev {
		return "it is a sequential run of characters", true
	}
	// The staples. Compared case-insensitively against the whole value, not as
	// substrings: a real ExternalId that happens to contain "test" is fine.
	for _, bad := range []string{
		"password", "passw0rd", "secret", "changeme", "letmein", "qwerty",
		"external-id", "externalid", "placeholder", "todo", "example",
		"test", "testing", "temporary", "temp", "automat",
	} {
		if lower == bad || strings.HasPrefix(lower, bad) && isPaddingOnly(lower[len(bad):]) {
			return fmt.Sprintf("it is %q with padding, which is the first thing anyone guesses", bad), true
		}
	}
	return "", false
}

// isPaddingOnly reports whether s is only the filler someone adds to get a value
// past a length check: a few digits or separators, nothing more.
//
// Bounded, because unbounded it produced a false positive on a real value. When
// automat generated ExternalIds they began "automat-", and "automat" is on the staple
// list, so a genuine crypto/rand value whose suffix happened to be all digits was
// reported as a guessable placeholder. That generator is gone, but the bound stays and
// the reasoning still holds: refusing a correctly generated secret is the worse
// failure of the two, because it sends the operator looking for a problem in the one
// part of this that was right.
//
// maxPadding is comfortably over the "1234"/"01"/"!!" a human appends to get past a
// length check, and well under the tail of any value worth calling a secret.
func isPaddingOnly(s string) bool {
	const maxPadding = 8
	if len(s) > maxPadding {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isFiller := c == '-' || c == '_' || c == '.' || c == '!'
		if !isDigit && !isFiller {
			return false
		}
	}
	return true
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
