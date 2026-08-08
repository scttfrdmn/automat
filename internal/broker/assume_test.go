// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/awsfake"
)

const (
	vendorRole = "arn:aws:iam::111111111111:role/automat-vendor"
	memberAcct = "222222222222"
)

// TestAssumeSendsTheResolvedExternalId is the property the whole package
// exists for: a trust policy requiring an ExternalId only defends the role if
// the caller actually sends the value the reference resolves to, not the
// reference itself.
func TestAssumeSendsTheResolvedExternalId(t *testing.T) {
	t.Setenv("AUTOMAT_TEST_BROKER_EXTID", "a-real-external-id-value")
	sts := awsfake.NewSTS(memberAcct)
	sts.Assumable[vendorRole] = "a-real-external-id-value"

	cfg, err := Assume(context.Background(), sts, vendorRole, "env:AUTOMAT_TEST_BROKER_EXTID", "us-east-1")
	if err != nil {
		t.Fatalf("Assume: %v", err)
	}
	if got := aws.ToString(sts.LastAssumeRole.ExternalId); got != "a-real-external-id-value" {
		t.Errorf("sent ExternalId %q, want the resolved value, not the reference", got)
	}
	if got := aws.ToString(sts.LastAssumeRole.RoleSessionName); got == "" {
		t.Error("no RoleSessionName sent; CloudTrail would show an anonymous assumption")
	}
	if cfg.Region != "us-east-1" {
		t.Errorf("Config.Region = %q, want us-east-1", cfg.Region)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve credentials from the returned Config: %v", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		t.Errorf("returned Config's credentials are incomplete: %+v", creds)
	}
}

// TestAssumeWithNoExternalIdRefSendsNone covers the legitimate-but-weaker
// configuration preflight.checkVendorRole already flags: a role whose trust
// policy requires no ExternalId at all.
func TestAssumeWithNoExternalIdRefSendsNone(t *testing.T) {
	sts := awsfake.NewSTS(memberAcct)
	sts.Assumable[vendorRole] = "" // trust policy requires no ExternalId

	if _, err := Assume(context.Background(), sts, vendorRole, "", "us-east-1"); err != nil {
		t.Fatalf("Assume: %v", err)
	}
	if got := sts.LastAssumeRole.ExternalId; got != nil {
		t.Errorf("sent ExternalId %q with no ref configured; must send none", aws.ToString(got))
	}
}

// TestAssumeRefusesAnUnresolvableExternalIdWithoutCallingAssumeRole. A
// misconfigured reference (unset env var, missing file) must fail before
// anything reaches STS — sending no ExternalId when one was configured would
// either succeed against a misconfigured-but-permissive role (masking the
// operator's mistake) or fail with the same undifferentiated AccessDenied every
// other assumption failure produces, hiding a config problem behind an AWS one.
func TestAssumeRefusesAnUnresolvableExternalIdWithoutCallingAssumeRole(t *testing.T) {
	sts := awsfake.NewSTS(memberAcct)
	sts.Assumable[vendorRole] = "" // would succeed if Assume ignored the resolve error

	_, err := Assume(context.Background(), sts, vendorRole, "env:AUTOMAT_TEST_BROKER_UNSET", "us-east-1")
	if err == nil {
		t.Fatal("Assume succeeded with an unresolvable ExternalId reference")
	}
	if n := sts.CallCount("AssumeRole"); n != 0 {
		t.Errorf("AssumeRole called %d times; a resolve failure must not reach STS at all", n)
	}
	if !strings.Contains(err.Error(), "AUTOMAT_TEST_BROKER_UNSET") {
		t.Errorf("error does not name the unset variable: %v", err)
	}
}

// TestAssumeRemediationNamesTheGrant is CLAUDE.md rule 7: a permission failure
// must say which action, which resource, and what grant would fix it. Modeled
// on preflight's TestVendorRoleIsAssumedNotSimulated sibling so the same
// failure reads the same way whether it happened during preflight or during a
// vend.
func TestAssumeRemediationNamesTheGrant(t *testing.T) {
	sts := awsfake.NewSTS(memberAcct)
	// vendorRole absent from Assumable: not trusted, or wrong ExternalId — AWS
	// will not say which.

	_, err := Assume(context.Background(), sts, vendorRole, "", "us-east-1")
	if err == nil {
		t.Fatal("Assume succeeded against a role that does not trust this caller")
	}
	pe, ok := awsapi.AsPermissionError(err)
	if !ok {
		t.Fatalf("error is not a *awsapi.PermissionError: %v", err)
	}
	if pe.Action != "sts:AssumeRole" {
		t.Errorf("Action = %q, want sts:AssumeRole", pe.Action)
	}
	if pe.Resource != vendorRole {
		t.Errorf("Resource = %q, want %q", pe.Resource, vendorRole)
	}
	for _, want := range []string{"trust", "ExternalId", "setup --request"} {
		if !strings.Contains(pe.Grant, want) {
			t.Errorf("Grant does not mention %q: %s", want, pe.Grant)
		}
	}
}

// TestAssumeRemediationDistinguishesWhetherAnExternalIdWasSent. Both failure
// shapes must still name both requirements — AWS does not say which one broke —
// but the grant text should tell the operator which input was actually sent so
// they don't waste time checking a value that was never on the wire.
func TestAssumeRemediationDistinguishesWhetherAnExternalIdWasSent(t *testing.T) {
	t.Setenv("AUTOMAT_TEST_BROKER_EXTID2", "a-wrong-but-well-formed-value")

	sts := awsfake.NewSTS(memberAcct)
	sts.Assumable[vendorRole] = "a-real-external-id-value" // caller will send the wrong one

	_, err := Assume(context.Background(), sts, vendorRole, "env:AUTOMAT_TEST_BROKER_EXTID2", "us-east-1")
	if err == nil {
		t.Fatal("Assume succeeded with the wrong ExternalId")
	}
	pe, ok := awsapi.AsPermissionError(err)
	if !ok {
		t.Fatalf("error is not a *awsapi.PermissionError: %v", err)
	}
	if !strings.Contains(pe.Grant, "An ExternalId was sent") {
		t.Errorf("Grant does not say an ExternalId was sent: %s", pe.Grant)
	}

	sts2 := awsfake.NewSTS(memberAcct)
	sts2.Assumable[vendorRole] = "a-required-external-id-value" // role requires one; caller sends none

	_, err2 := Assume(context.Background(), sts2, vendorRole, "", "us-east-1")
	if err2 == nil {
		t.Fatal("Assume succeeded against a role requiring an ExternalId, with none sent")
	}
	pe2, ok := awsapi.AsPermissionError(err2)
	if !ok {
		t.Fatalf("error is not a *awsapi.PermissionError: %v", err2)
	}
	if !strings.Contains(pe2.Grant, "No ExternalId was sent") {
		t.Errorf("Grant does not say no ExternalId was sent: %s", pe2.Grant)
	}
}

// TestAssumedConfigBuildsAWorkingOrgVendAPIClient is the actual point of the
// package: the returned Config is not merely well-formed, it produces a client
// satisfying awsapi.OrgVendAPI. This does not call real AWS — it only checks
// that organizations.NewFromConfig accepts the Config and returns something
// implementing the interface, which is a compile-and-construct check rather
// than a network one.
func TestAssumedConfigBuildsAWorkingOrgVendAPIClient(t *testing.T) {
	sts := awsfake.NewSTS(memberAcct)
	sts.Assumable[vendorRole] = ""

	cfg, err := Assume(context.Background(), sts, vendorRole, "", "us-east-1")
	if err != nil {
		t.Fatalf("Assume: %v", err)
	}
	var _ awsapi.OrgVendAPI = organizations.NewFromConfig(cfg)
}
