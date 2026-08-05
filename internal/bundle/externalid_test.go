// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"strings"
	"testing"
)

// TestAPlaceholderExternalIDIsRefused. Length and charset were the only checks, so
// `--external-id 0000000000000000` and `--external-id password12345678` both
// validated and were written into a trust policy as the confused-deputy condition.
//
// The flag has to exist -- re-sending a bundle for a deployed role must reproduce
// the value that role already trusts -- so it cannot require the generated form.
// This is the degenerate end only, and passing it proves nothing; see
// weakExternalID's comment.
func TestAPlaceholderExternalIDIsRefused(t *testing.T) {
	for _, v := range []string{
		"0000000000000000",
		"aaaaaaaaaaaaaaaaaaaa",
		"1234567890123456",
		"abcdefghijklmnop",
		"password12345678",
		"changeme12345678",
		"placeholder-1234",
		"externalid000000",
		"TEST--------",
	} {
		r := validRequest()
		r.ExternalID = v
		err := r.Validate()
		if err == nil {
			t.Errorf("accepted %q as an ExternalId — its only property is being unguessable", v)
			continue
		}
		// The reason must be given, and the value must not be: an ExternalId in an
		// error message ends up in scrollback and pasted issue reports, and the
		// operator may have supplied a live one by mistake.
		if !strings.Contains(err.Error(), "external_id") {
			t.Errorf("%q: the error does not name the field: %v", v, err)
		}
		if strings.Contains(err.Error(), v) {
			t.Errorf("%q: the error echoes the value: %v", v, err)
		}
	}
}

// TestAGeneratedExternalIDIsNeverCalledWeak is the other half, and the half that
// matters more: refusing a correctly generated secret sends the operator looking for
// a problem in the one part of this that was right.
//
// The generated form starts with "automat-", and "automat" is on the staple list, so
// this came within an unbounded padding check of rejecting real values.
func TestAGeneratedExternalIDIsNeverCalledWeak(t *testing.T) {
	for i := 0; i < 2000; i++ {
		v, err := NewExternalID()
		if err != nil {
			t.Fatalf("NewExternalID: %v", err)
		}
		if reason, weak := weakExternalID(v); weak {
			t.Fatalf("a generated ExternalId was called weak (%s): %q", reason, v)
		}
		r := validRequest()
		r.ExternalID = v
		if verr := r.Validate(); verr != nil {
			t.Fatalf("a generated ExternalId failed validation: %v", verr)
		}
	}

	// And the specific shape that broke it: the prefix followed by digits only.
	// Base32 uses A-Z and 2-7, so an all-digit suffix is improbable, not impossible.
	if reason, weak := weakExternalID("automat-234567234567234567234567234567"); weak {
		t.Errorf("a generated-shape value with an all-digit base32 suffix was called weak (%s) — "+
			"the padding check must stay bounded", reason)
	}
}

// TestAnExternalIDFromADeployedTrustPolicyStillWorks. The flag's entire purpose is
// re-sending a bundle for a role that already exists, so a value automat would not
// have generated must still be accepted. A check that only accepts automat's own
// output makes the flag useless and pushes the operator to hand-edit the templates.
func TestAnExternalIDFromADeployedTrustPolicyStillWorks(t *testing.T) {
	for _, v := range []string{
		"7f3a91c0e4b2d8a6f5e1",
		"vendor-tenant-4f9a2b1c8e",
		"acct:9912:role:vend:1f4a",
		"OldToolExternalId2024xyz",
	} {
		r := validRequest()
		r.ExternalID = v
		if err := r.Validate(); err != nil {
			t.Errorf("refused %q, which a deployed trust policy may already require: %v", v, err)
		}
	}
}
