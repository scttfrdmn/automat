// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"regexp"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/config"
)

// TestNoRenderedFileContainsAnExternalIDValue is the mechanism the AUDIT-1 review
// asked for in place of a paragraph.
//
// The bundle used to carry a live sts:ExternalId in both role templates, mitigated by
// a README paragraph telling the operator not to commit it. This asserts the property
// that replaced it: no generated file contains a value in the ExternalId position at
// all. The templates name the *input* — `!Ref AutomatExternalId`,
// `var.automat_external_id` — and a future edit that interpolates a literal there
// fails here rather than shipping a secret-bearing artifact with a green suite.
//
// Keyed to what follows `sts:ExternalId` rather than searching for a known value,
// because there is no known value to search for. That is the point: a test that looked
// for a specific string would pass on any *other* secret appearing in the same slot.
func TestNoRenderedFileContainsAnExternalIDValue(t *testing.T) {
	// The two shapes the trust condition takes, one per template dialect. Anything
	// else on the right-hand side is a literal.
	allowed := []string{
		"!Ref AutomatExternalId",
		"var.automat_external_id",
	}
	// Matches the condition line in either dialect and captures the right-hand side.
	re := regexp.MustCompile(`sts:ExternalId"?\s*[:=]\s*(.+)`)

	for _, r := range []*Request{validRequest(), validRequestNewOU()} {
		for _, rd := range renderers {
			data, err := rd.render(r)
			if err != nil {
				t.Fatalf("%s: %v", rd.name, err)
			}
			for i, line := range strings.Split(string(data), "\n") {
				m := re.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				rhs := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m[1]), "}"))
				rhs = strings.TrimSpace(strings.TrimSuffix(rhs, ","))
				ok := false
				for _, a := range allowed {
					if rhs == a {
						ok = true
					}
				}
				if !ok {
					t.Errorf("%s:%d assigns something other than the deploy-time input to "+
						"sts:ExternalId (%q) — the bundle must not carry the value; the templates "+
						"declare it as a parameter and whoever deploys the role supplies it",
						rd.name, i+1, rhs)
				}
			}
		}
	}
}

// TestBothTemplatesDeclareTheExternalIDAsADeployTimeInput. The test above proves no
// literal is present; this proves the input actually exists. Without it, deleting the
// Parameters block would satisfy the other test perfectly — a trust policy with no
// ExternalId condition at all contains no ExternalId literal either.
func TestBothTemplatesDeclareTheExternalIDAsADeployTimeInput(t *testing.T) {
	for _, tc := range []struct {
		file   string
		render func(*Request) ([]byte, error)
		want   []string
	}{
		{FileRoleCFN, VendorRoleCFN, []string{
			"AutomatExternalId:",
			"NoEcho: true",
			"sts:ExternalId: !Ref AutomatExternalId",
		}},
		{FileRoleTF, VendorRoleTF, []string{
			`variable "automat_external_id"`,
			"sensitive = true",
			`"sts:ExternalId" = var.automat_external_id`,
		}},
	} {
		data, err := tc.render(validRequest())
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		for _, want := range tc.want {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s does not contain %q — the ExternalId must be a declared "+
					"deploy-time input, marked as a secret, and referenced by the trust policy",
					tc.file, want)
			}
		}
	}
}

// TestTheTemplateBoundsAreTheResolversBounds.
//
// The templates constrain a value automat will later *consume* through
// config.ResolveExternalID. If the template accepted what the resolver refuses, central
// IT would deploy a working role that automat cannot use — and would find out at assume
// time, from an opaque AccessDenied, having already approved the bundle. If the template
// were narrower than AWS, it would refuse a trust policy value that predates automat.
//
// The constants are aliases, so this cannot fail by drift; it can fail by someone
// re-declaring them locally, which is exactly what the aliases replaced.
func TestTheTemplateBoundsAreTheResolversBounds(t *testing.T) {
	if minExternalIDChars != config.MinExternalIDChars {
		t.Errorf("the template's minimum (%d) is not the resolver's (%d)",
			minExternalIDChars, config.MinExternalIDChars)
	}
	if maxExternalIDChars != config.MaxExternalIDChars {
		t.Errorf("the template's maximum (%d) is not the resolver's (%d)",
			maxExternalIDChars, config.MaxExternalIDChars)
	}
	if externalIDPattern != config.ExternalIDCharset+"+" {
		t.Errorf("the template's pattern (%q) is not the resolver's charset (%q)",
			externalIDPattern, config.ExternalIDCharset)
	}

	// And the rendered form, which is where a formatting mistake would land: the
	// bounds must reach both files as the numbers above, not as whatever a later
	// edit hardcodes beside them.
	cfn, err := VendorRoleCFN(validRequest())
	if err != nil {
		t.Fatalf("VendorRoleCFN: %v", err)
	}
	for _, want := range []string{
		"MinLength: 16",
		"MaxLength: 1224",
		"AllowedPattern: '[A-Za-z0-9+=,.@:/_-]+'",
	} {
		if !strings.Contains(string(cfn), want) {
			t.Errorf("%s does not contain %q", FileRoleCFN, want)
		}
	}
	tf, err := VendorRoleTF(validRequest())
	if err != nil {
		t.Fatalf("VendorRoleTF: %v", err)
	}
	for _, want := range []string{
		`regex("^[A-Za-z0-9+=,.@:/_-]+$", var.automat_external_id)`,
		">= 16 && length(var.automat_external_id) <= 1224",
	} {
		if !strings.Contains(string(tf), want) {
			t.Errorf("%s does not contain %q", FileRoleTF, want)
		}
	}
}

// TestTheREADMETellsCentralITToGenerateTheValueItself.
//
// The disclosure paragraph the review rejected became a mechanism, and this holds the
// document to the mechanism's shape: the reader has to be told they generate the value,
// how, that it travels separately from the bundle, and that they should not accept one
// from the requester. That last instruction is the one with teeth — a management account
// that accepts an ExternalId from the party it is granting access to has delegated its
// own confused-deputy defense to them.
func TestTheREADMETellsCentralITToGenerateTheValueItself(t *testing.T) {
	data, err := README(validRequest())
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	// Whitespace-normalized: the README is hard-wrapped, so any phrase here can
	// straddle a line break, and pinning the wrap point would fail a security test on
	// an editorial reflow.
	s := strings.Join(strings.Fields(string(data)), " ")

	for _, tc := range []struct{ want, why string }{
		{"contains no secret", "the reader must be told the bundle is safe to forward, or they will treat it as a secret and the out-of-band step will look redundant"},
		{"you choose that value", "the reader must be told the choice is theirs"},
		{"openssl rand", "an instruction to generate a secret without a way to do it invites a typed one"},
		{"out of band", "the value must not travel with the bundle"},
		{"Do not accept an ExternalId from the requester", "accepting the grantee's value delegates the defense to them"},
	} {
		if !strings.Contains(s, tc.want) {
			t.Errorf("the README does not say %q — %s", tc.want, tc.why)
		}
	}

	// The claim retired with the mechanism. If this sentence comes back while the
	// templates take a parameter, the README is describing a bundle that no longer
	// exists — and describing it as more dangerous than it is, which trains the
	// reader to discount the parts that are true.
	if strings.Contains(s, "contains a live `sts:ExternalId`") {
		t.Error("the README still claims the bundle carries a live ExternalId, which it does not")
	}

	// And it must not contradict the .gitignore automat writes into the same
	// directory. Saying "the bundle contains no secret" is true and worth saying;
	// concluding "so you can commit it" — which this README did on the first pass —
	// puts two generated files in one directory giving opposite instructions, and the
	// reader resolves that by deciding one of automat's files is wrong. Removing a
	// secret is a reason to stop warning about a credential, not a reason to
	// recommend the thing the bundle's own .gitignore prevents.
	if strings.Contains(s, "or commit it") {
		t.Error("the README tells the reader they may commit the bundle, which contradicts " +
			"the .gitignore in the same directory")
	}
}
