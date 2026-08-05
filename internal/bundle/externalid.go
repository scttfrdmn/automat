// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// ExternalId generation.
//
// `setup --request` needs a value for the trust policy's sts:ExternalId condition,
// and where it comes from is a security decision rather than a formatting one, so
// it lives in its own function with the argument attached.
//
// # Why it is generated rather than chosen
//
// An operator asked to invent this value will pick something memorable, and a
// memorable ExternalId is a guessable one. Its entire job is to be a value a third
// party who knows the role ARN was never told — DESIGN §5's confused-deputy
// defense — and it stops doing that job the moment it is derivable from the
// institution's name, the OU, or the date. So automat generates it from
// crypto/rand and never offers a way to supply a shorter one.
//
// # What --external-id can and cannot be checked for
//
// `--external-id` exists for one case: re-sending a bundle for a role that already
// exists, where the value has to match the trust policy already deployed. So it must
// accept a value automat did not generate, which means it cannot require the
// generated form — and automat cannot measure the entropy of a string. "correct
// horse battery staple" and 20 bytes of crypto/rand are the same length and the same
// charset.
//
// What it can refuse is the degenerate end, where the value is not a secret in any
// sense: a single repeated character, a run of digits, or one of the handful of
// strings people actually type when a tool demands a token. weakExternalID does that
// and nothing more. It is a typo-and-placeholder check, not a strength meter, and
// treating it as one would be the more dangerous mistake — passing it says nothing
// about a value's unguessability, which is why the flag's help text tells the
// operator to let automat generate one rather than reassuring them that theirs was
// accepted.
//
// # Why it is not derived from anything
//
// A tempting design is to derive it from the account id and OU, so both sides can
// recompute it and it never has to be transmitted. That is exactly wrong: the
// inputs are public, so anyone who can read the role's trust policy — or guess an
// account number — can recompute the value the trust policy checks. A derived
// ExternalId is a constant dressed as a secret.
const (
	// externalIDBytes is 160 bits of entropy. AWS permits 2–1224 characters; this
	// is far above the point where guessing is the attack, and short enough to
	// paste into a ticket without wrapping.
	externalIDBytes = 20
	// externalIDPrefix makes the value self-describing in a trust policy someone
	// reads a year later, and greppable in a config file.
	externalIDPrefix = "automat-"
)

// NewExternalID returns a fresh ExternalId.
//
// The encoding is unpadded, uppercase base32 with a prefix: it survives being
// copied out of an email, typed by a human, and pasted into TOML, JSON, and YAML
// without quoting questions, and it contains no character that Request.Validate
// would refuse. Base64 would be shorter and would sometimes contain a `+` or `/`,
// which is how a value ends up mangled by whatever transport central IT uses.
func NewExternalID() (string, error) {
	buf := make([]byte, externalIDBytes)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not a condition to paper over with a fallback:
		// a predictable ExternalId would silently remove the confused-deputy
		// defense while leaving every document that mentions it unchanged.
		return "", fmt.Errorf("generate an ExternalId: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	return externalIDPrefix + strings.ToUpper(enc), nil
}

// weakExternalID reports whether v is degenerate enough that it is not a secret in
// any sense, and a short reason if so.
//
// Deliberately a small, closed list rather than a strength heuristic. An ExternalId
// that passes this is not thereby unguessable — nothing automat can compute would
// tell it that — so the check only catches the cases where the operator has clearly
// typed a placeholder: one repeated character, a digit run, or a password-list
// staple. Anything cleverer would be a strength meter, and a strength meter that says
// "ok" is a claim automat cannot support.
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
// Bounded, because unbounded it produced a false positive on a real value. The
// generated form starts with "automat-" and "automat" is on the staple list, so
// a genuine crypto/rand ExternalId whose base32 suffix happened to be all digits —
// base32's alphabet is A-Z and 2-7, so that is unlikely but perfectly possible —
// was reported as a guessable placeholder. Refusing a correctly generated secret is
// the worse failure of the two: it sends the operator looking for a problem in the
// one part of this that was right.
//
// maxPadding is well under the 32 characters a generated suffix has, and comfortably
// over the "1234"/"01"/"!!" that a human appends to get past a length check.
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
