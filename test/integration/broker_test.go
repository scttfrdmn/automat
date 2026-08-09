// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package integration holds automat's emulator-backed tests: the ones
// docs/testing-strategy.md says internal/awsfake structurally cannot express.
//
// Separate module, deliberately (CLAUDE.md, docs/testing-strategy.md): substrate
// requires go 1.26, ahead of automat's own go 1.24 floor, and a dependency's go
// directive propagates to `go install` for everyone in the same module
// regardless of which files import it. Run via `make integration` from the
// repo root, never from the default `make test` gate.
package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/scttfrdmn/substrate/emulator"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/broker"
)

// unauthenticatedConfig points an SDK config at a running substrate TestServer
// with substrate's documented unauthenticated credentials. "test"/"test"
// resolves to no IAM principal, so calls made with it are authorized against
// nothing — which is exactly what makes it safe for setup calls (CreateUser,
// CreateRole) that this suite does not want gated by an identity policy of
// their own.
func unauthenticatedConfig(t *testing.T, ts *emulator.TestServer) aws.Config {
	t.Helper()
	return mustLoadConfig(t, ts, "test", "test")
}

func mustLoadConfig(t *testing.T, ts *emulator.TestServer, accessKeyID, secretAccessKey string) aws.Config {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithBaseEndpoint(ts.URL),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

const (
	// memberAccountID is substrate's default account id (docs/services.md:
	// "GetCallerIdentity returns account 123456789012 by default"). Substrate
	// emulates one account per server unless configured otherwise, so the
	// signed caller created below and the role's trust policy are necessarily
	// in the same account — this is not automat's own test fixture id
	// (internal/awsfake's is 222222222222), and using that value here would
	// name an account the emulator itself is not.
	memberAccountID = "123456789012"
	vendorRoleName  = "automat-vendor"
	testExternalID  = "test-external-id-value"
)

func roleARN(name string) string {
	return "arn:aws:iam::" + memberAccountID + ":role/" + name
}

// signedMemberCaller creates an IAM user with permission to call
// sts:AssumeRole, mints an access key for it, and returns an SDK config signed
// as that user — a REAL principal, unlike the unauthenticated "test"/"test"
// credentials, and the only kind substrate's trust-policy evaluator will check
// a role's Principal/Condition block against (substrate's testing guide:
// "existence in state is the opt-in" — an unsigned or unregistered caller is
// never authorized against anything, including a trust policy).
func signedMemberCaller(t *testing.T, ts *emulator.TestServer) aws.Config {
	t.Helper()
	setup := iam.NewFromConfig(unauthenticatedConfig(t, ts))
	const userName = "automat-member-caller"
	if _, err := setup.CreateUser(context.Background(),
		&iam.CreateUserInput{UserName: aws.String(userName)}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := setup.PutUserPolicy(context.Background(), &iam.PutUserPolicyInput{
		UserName:   aws.String(userName),
		PolicyName: aws.String("may-assume"),
		PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`),
	}); err != nil {
		t.Fatalf("PutUserPolicy: %v", err)
	}
	out, err := setup.CreateAccessKey(context.Background(),
		&iam.CreateAccessKeyInput{UserName: aws.String(userName)})
	if err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	return mustLoadConfig(t, ts, aws.ToString(out.AccessKey.AccessKeyId), aws.ToString(out.AccessKey.SecretAccessKey))
}

// createVendorRole creates the role with a trust policy admitting
// memberAccountID's root, conditioned on testExternalID — the same shape
// internal/bundle.VendorRoleTrustPolicyJSON renders for a real onboarding.
func createVendorRole(t *testing.T, ts *emulator.TestServer) {
	t.Helper()
	iamClient := iam.NewFromConfig(unauthenticatedConfig(t, ts))
	_, err := iamClient.CreateRole(context.Background(), &iam.CreateRoleInput{
		RoleName: aws.String(vendorRoleName),
		AssumeRolePolicyDocument: aws.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::` + memberAccountID + `:root"},
				"Action": "sts:AssumeRole",
				"Condition": {"StringEquals": {"sts:ExternalId": "` + testExternalID + `"}}
			}]
		}`),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
}

// TestBrokerAssumeSucceedsWithTheRightExternalId is the property Task 4 was
// scoped to test (ROADMAP.md): substrate now evaluates a role's trust policy —
// including sts:ExternalId — on AssumeRole (substrate#593, fixed in v0.95.0),
// which is what makes this reachable at all. Before v0.95.0, every caller with
// any ExternalId assumed any role that existed; this test would have passed for
// the wrong reason then, which is why it did not exist until now.
//
// Calls the raw STS API directly rather than broker.Assume, to isolate "does
// substrate admit the correct ExternalId" from "does broker.Assume plumb a
// resolved value through correctly" — the latter is
// TestBrokerAssumeFailsWithNoExternalId's job, via the real call path.
func TestBrokerAssumeSucceedsWithTheRightExternalId(t *testing.T) {
	ts := emulator.StartTestServer(t)
	createVendorRole(t, ts)
	cfg := signedMemberCaller(t, ts)
	stsClient := sts.NewFromConfig(cfg)

	out, err := stsClient.AssumeRole(context.Background(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN(vendorRoleName)),
		RoleSessionName: aws.String("automat-vend"),
		ExternalId:      aws.String(testExternalID),
	})
	if err != nil {
		t.Fatalf("AssumeRole with the correct ExternalId was refused: %v", err)
	}
	if out.Credentials == nil || aws.ToString(out.Credentials.AccessKeyId) == "" {
		t.Fatal("AssumeRole succeeded but returned no usable credentials")
	}
	if !strings.HasPrefix(aws.ToString(out.Credentials.AccessKeyId), "ASIA") {
		t.Errorf("access key %q does not have the ASIA prefix real STS session credentials carry",
			aws.ToString(out.Credentials.AccessKeyId))
	}
}

// TestBrokerAssumeFailsWithNoExternalId is the confused-deputy defense itself,
// exercised through broker.Assume exactly as internal/broker's own package
// calls it: a signed caller the trust policy's Principal admits, but with no
// ExternalId at all, must be refused. Before substrate v0.95.0 this call
// succeeded — that regression is what this test exists to catch if it recurs.
func TestBrokerAssumeFailsWithNoExternalId(t *testing.T) {
	ts := emulator.StartTestServer(t)
	createVendorRole(t, ts)
	cfg := signedMemberCaller(t, ts)
	stsClient := sts.NewFromConfig(cfg)

	_, err := broker.Assume(context.Background(), stsClient, roleARN(vendorRoleName), "", "us-east-1")
	if err == nil {
		t.Fatal("broker.Assume succeeded with no ExternalId against a role requiring one")
	}
	pe, ok := awsapi.AsPermissionError(err)
	if !ok {
		t.Fatalf("error is not a *awsapi.PermissionError: %v", err)
	}
	if pe.Action != "sts:AssumeRole" {
		t.Errorf("Action = %q, want sts:AssumeRole", pe.Action)
	}
	for _, want := range []string{"trust", "ExternalId"} {
		if !strings.Contains(pe.Grant, want) {
			t.Errorf("Grant does not mention %q: %s", want, pe.Grant)
		}
	}
}

// TestBrokerAssumeFailsForAnUntrustedPrincipal is the other half of the trust
// policy: a caller not named by Principal at all, correct ExternalId
// notwithstanding — the shape a role trusting a different member account, or a
// vendor role someone else's onboarding bundle deployed, would produce.
func TestBrokerAssumeFailsForAnUntrustedPrincipal(t *testing.T) {
	ts := emulator.StartTestServer(t)
	iamClient := iam.NewFromConfig(unauthenticatedConfig(t, ts))
	_, err := iamClient.CreateRole(context.Background(), &iam.CreateRoleInput{
		RoleName: aws.String(vendorRoleName),
		AssumeRolePolicyDocument: aws.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::999999999999:root"},
				"Action": "sts:AssumeRole",
				"Condition": {"StringEquals": {"sts:ExternalId": "` + testExternalID + `"}}
			}]
		}`),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	cfg := signedMemberCaller(t, ts) // an account-123456789012 identity, not 999999999999

	_, err = broker.Assume(context.Background(), sts.NewFromConfig(cfg), roleARN(vendorRoleName),
		"", "us-east-1")
	if err == nil {
		t.Fatal("broker.Assume succeeded against a role trusting a different account")
	}
	if _, ok := awsapi.AsPermissionError(err); !ok {
		t.Fatalf("error is not a *awsapi.PermissionError: %v", err)
	}
}

// TestBrokerAssumeIsRejectedForAnUnknownRole is a real HTTP-level
// NoSuchEntityException parsed correctly by the AWS SDK — exactly the class of
// thing a fake cannot get wrong by construction, because the fake never parses
// an error off the wire. Distinct from the trust-policy tests above: this is
// "the role does not exist", not "the role exists and refuses this caller".
func TestBrokerAssumeIsRejectedForAnUnknownRole(t *testing.T) {
	ts := emulator.StartTestServer(t)
	cfg := unauthenticatedConfig(t, ts)
	stsClient := sts.NewFromConfig(cfg)

	_, err := broker.Assume(context.Background(), stsClient,
		roleARN("role-that-was-never-created"), "", "us-east-1")
	if err == nil {
		t.Fatal("Assume succeeded against a role nothing created")
	}
	if pe, ok := awsapi.AsPermissionError(err); ok {
		t.Fatalf("a missing role surfaced as a PermissionError, which reads as an authorization "+
			"problem rather than a configuration one: %v", pe)
	}
}
