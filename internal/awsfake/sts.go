// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// STS fakes awsapi.STSAPI.
type STS struct {
	Recorder

	// AccountID and ARN are what GetCallerIdentity reports.
	AccountID string
	ARN       string
	// IdentityErr, if set, fails GetCallerIdentity.
	IdentityErr error

	// Assumable maps a role ARN to the ExternalId it requires. A role absent
	// from the map is not assumable and returns AccessDenied — the shape of the
	// MEMBER-without-grants case that produces the onboarding bundle.
	Assumable map[string]string
	// AssumedAccount is the account id credentials from AssumeRole belong to.
	AssumedAccount string

	// LastAssumeRole records the most recent input, so a test can assert that
	// automat sent an ExternalId at all: a trust policy requiring one is only
	// protective if the caller actually supplies it (DESIGN §5).
	LastAssumeRole *sts.AssumeRoleInput
}

// NewSTS returns an STS fake for a caller in the given account.
func NewSTS(accountID string) *STS {
	return &STS{
		AccountID:      accountID,
		ARN:            "arn:aws:sts::" + accountID + ":assumed-role/operator/session",
		Assumable:      map[string]string{},
		AssumedAccount: accountID,
	}
}

// GetCallerIdentity implements awsapi.STSAPI.
func (f *STS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.Record("GetCallerIdentity")
	if f.IdentityErr != nil {
		return nil, f.IdentityErr
	}
	return &sts.GetCallerIdentityOutput{
		Account: aws.String(f.AccountID),
		Arn:     aws.String(f.ARN),
		UserId:  aws.String("AROAEXAMPLE:session"),
	}, nil
}

// AssumeRole implements awsapi.STSAPI.
//
// A wrong or missing ExternalId is rejected the way AWS rejects it: with
// AccessDenied and no hint about which of the two was wrong. Reproducing that
// bluntness is the point — automat's remediation text has to be useful without
// the API telling it what failed.
func (f *STS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput,
	_ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.Record("AssumeRole")
	f.LastAssumeRole = in

	roleARN := aws.ToString(in.RoleArn)
	want, ok := f.Assumable[roleARN]
	if !ok {
		return nil, AccessDenied("sts:AssumeRole on " + roleARN)
	}
	if want != aws.ToString(in.ExternalId) {
		return nil, AccessDenied("sts:AssumeRole on " + roleARN)
	}
	return &sts.AssumeRoleOutput{
		AssumedRoleUser: &ststypes.AssumedRoleUser{
			Arn:           aws.String(roleARN + "/" + aws.ToString(in.RoleSessionName)),
			AssumedRoleId: aws.String("AROAFAKE:" + aws.ToString(in.RoleSessionName)),
		},
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("ASIAFAKEACCESSKEY"),
			SecretAccessKey: aws.String("fake-secret-not-a-credential"),
			SessionToken:    aws.String("fake-session-token"),
			// A fixed expiry: tests must not depend on wall-clock time, and a
			// deterministic value keeps golden output stable.
			Expiration: aws.Time(time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC)),
		},
	}, nil
}

var _ awsapi.STSAPI = (*STS)(nil)
