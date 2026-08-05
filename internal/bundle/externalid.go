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
