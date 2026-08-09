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

// substrateClientConfig points an SDK config at a running substrate TestServer.
// "test"/"test" resolves to no IAM principal (substrate's testing guide: a
// caller must exist in state to be authorized against anything), which is what
// lets CreateRole below succeed unconditionally — the property under test is
// AssumeRole's behavior, not who may call CreateRole.
func substrateClientConfig(t *testing.T, ts *emulator.TestServer) aws.Config {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithBaseEndpoint(ts.URL),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

// TestBrokerAssumeAgainstARealSTSServer is what internal/awsfake structurally
// cannot express: broker.Assume's HTTP round trip — request signing, XML
// marshaling, response parsing — against a server that actually implements the
// STS wire protocol, rather than a Go struct built to answer however the fake
// was written.
//
// # What this does NOT prove, and why
//
// It does not prove the vendor role's trust policy or its ExternalId condition
// is enforced. Substrate's AssumeRole (as of the version this module pins)
// checks only that the named role exists — it does not read
// AssumeRolePolicyDocument and does not evaluate the caller or an ExternalId
// against it, so an assumption from any caller with any ExternalId succeeds
// against any role that exists. That is the one property ROADMAP.md's Task 4
// section named as the reason to reach for an emulator here rather than
// duplicating awsfake.STS ("the emulator's auth controller IAM-enforces calls
// made with STS session credentials, so the test exercises the trust policy and
// the ExternalId condition"), and it is not yet true. Filed upstream as
// substrate#593. TestBrokerAssumeIsRejectedForAnUnknownRole below is the
// residual property that IS reachable today — a role absent from state — and
// it is the whole ExternalId-adjacent coverage this file can honestly claim.
//
// What it DOES prove: the credentials broker.Assume extracts from a real
// AssumeRole response are shaped correctly and produce a client
// (organizations.NewFromConfig, in production) that would send well-formed
// requests — the same wire-format-correctness argument
// docs/testing-strategy.md makes for reaching for an emulator over a fake.
func TestBrokerAssumeAgainstARealSTSServer(t *testing.T) {
	ts := emulator.StartTestServer(t)
	cfg := substrateClientConfig(t, ts)

	iamClient := iam.NewFromConfig(cfg)
	const roleName = "automat-vendor"
	_, err := iamClient.CreateRole(context.Background(), &iam.CreateRoleInput{
		RoleName: aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::222222222222:root"},
				"Action": "sts:AssumeRole",
				"Condition": {"StringEquals": {"sts:ExternalId": "test-external-id-value"}}
			}]
		}`),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	// The wrong ExternalId, sent on purpose: this is the call
	// TestBrokerAssumeAgainstARealSTSServer's own doc comment says substrate does
	// not yet refuse. Asserted explicitly, with a comment naming the filed
	// issue, so a future substrate upgrade that starts enforcing this turns the
	// assertion red instead of leaving a silent false negative in this suite —
	// see the check immediately after for how to notice that upgrade.
	gotCfg, err := broker.Assume(context.Background(), stsClient, roleARN(roleName),
		"", "us-east-1") // no ExternalId ref at all — the weakest possible input
	if err != nil {
		t.Fatalf("Assume with no ExternalId against a role requiring one unexpectedly failed "+
			"— if substrate#593 landed, this should now fail with AccessDenied, and this test "+
			"should be rewritten to assert that: %v", err)
	}
	creds, err := gotCfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve credentials from Assume's returned Config: %v", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		t.Fatalf("credentials from a real AssumeRole response are incomplete: %+v", creds)
	}
	if !strings.HasPrefix(creds.AccessKeyID, "ASIA") {
		t.Errorf("access key %q does not have the ASIA prefix real STS session credentials carry",
			creds.AccessKeyID)
	}
}

// TestBrokerAssumeIsRejectedForAnUnknownRole is the one trust-adjacent
// rejection substrate DOES implement today: a role absent from IAM state is
// refused with NoSuchEntityException, which broker.assumeError maps through
// awsapi.Denied's non-AccessDenied path. Not the ExternalId property — see the
// package doc — but a real HTTP-level NoSuchEntityException parsed correctly by
// the AWS SDK is exactly the class of thing a fake cannot get wrong by
// construction, because the fake never parses an error off the wire.
func TestBrokerAssumeIsRejectedForAnUnknownRole(t *testing.T) {
	ts := emulator.StartTestServer(t)
	cfg := substrateClientConfig(t, ts)
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

func roleARN(name string) string {
	return "arn:aws:iam::222222222222:role/" + name
}
