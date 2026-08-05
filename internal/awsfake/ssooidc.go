// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// SSOOIDC fakes awsapi.SSOOIDCAPI for the device authorization grant.
//
// PendingPolls is how many CreateToken calls return AuthorizationPendingException
// before one succeeds, which is the normal flow: the user has not finished
// approving in the browser yet. A login implementation that treats the first
// pending response as a failure would be unusable, and only a fake that can
// produce that response will catch it.
type SSOOIDC struct {
	Recorder

	PendingPolls int
	polls        int

	// AccessToken is what a successful CreateToken returns.
	AccessToken string
	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int32

	// RegisterErr, StartErr, TokenErr override each step.
	RegisterErr error
	StartErr    error
	TokenErr    error

	// LastRegister records the input, so a test can assert automat does not ask
	// for scopes beyond what it needs.
	LastRegister *ssooidc.RegisterClientInput
}

// NewSSOOIDC returns a fake that succeeds after n pending polls.
func NewSSOOIDC(pendingPolls int) *SSOOIDC {
	return &SSOOIDC{
		PendingPolls: pendingPolls,
		AccessToken:  "fake-access-token-not-a-credential",
		ExpiresIn:    3600,
	}
}

// RegisterClient implements awsapi.SSOOIDCAPI.
func (f *SSOOIDC) RegisterClient(_ context.Context, in *ssooidc.RegisterClientInput,
	_ ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	f.Record("RegisterClient")
	f.LastRegister = in
	if f.RegisterErr != nil {
		return nil, f.RegisterErr
	}
	return &ssooidc.RegisterClientOutput{
		ClientId:     aws.String("fake-client-id"),
		ClientSecret: aws.String("fake-client-secret-not-a-credential"),
	}, nil
}

// StartDeviceAuthorization implements awsapi.SSOOIDCAPI.
func (f *SSOOIDC) StartDeviceAuthorization(_ context.Context, _ *ssooidc.StartDeviceAuthorizationInput,
	_ ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	f.Record("StartDeviceAuthorization")
	if f.StartErr != nil {
		return nil, f.StartErr
	}
	return &ssooidc.StartDeviceAuthorizationOutput{
		DeviceCode:              aws.String("fake-device-code"),
		UserCode:                aws.String("FAKE-CODE"),
		VerificationUri:         aws.String("https://example.awsapps.com/start/#/device"),
		VerificationUriComplete: aws.String("https://example.awsapps.com/start/#/device?user_code=FAKE-CODE"),
		ExpiresIn:               600,
		// One second, so a poll loop under test does not sleep for the ten the
		// real API suggests.
		Interval: 1,
	}, nil
}

// CreateToken implements awsapi.SSOOIDCAPI.
func (f *SSOOIDC) CreateToken(_ context.Context, _ *ssooidc.CreateTokenInput,
	_ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	f.Record("CreateToken")
	if f.TokenErr != nil {
		return nil, f.TokenErr
	}
	if f.polls < f.PendingPolls {
		f.polls++
		return nil, &APIError{
			Code:    "AuthorizationPendingException",
			Message: "Authorization is still pending",
		}
	}
	return &ssooidc.CreateTokenOutput{
		AccessToken: aws.String(f.AccessToken),
		TokenType:   aws.String("Bearer"),
		ExpiresIn:   f.ExpiresIn,
	}, nil
}

var _ awsapi.SSOOIDCAPI = (*SSOOIDC)(nil)
