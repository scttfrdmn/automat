// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/config"
)

// globals holds what every subcommand needs: the resolved config context and a
// way to build AWS clients.
//
// The client constructors are fields rather than direct calls so a test can
// substitute internal/awsfake without a credential, a network, or an environment
// variable. CLAUDE.md rule 1 is that tests never reach AWS; the way to make that
// true is to make the fake path the same path, not a special case.
type globals struct {
	// configPath is where the config was loaded from, named in error messages so
	// an operator knows which file to edit.
	configPath string
	// contextName selects a context; empty means the default.
	contextName string

	// loaded is the parsed config, populated on first use.
	loaded *config.Config
	// found reports whether a config file existed at all, so "no config" can be
	// distinguished from "config without this setting".
	found bool

	// Client constructors, overridable in tests.
	newSSOOIDC func(ctx context.Context, region string) (awsapi.SSOOIDCAPI, error)
	newOrg     func(ctx context.Context, region, profile string) (awsapi.OrgAPI, error)
	newSTS     func(ctx context.Context, region, profile string) (awsapi.STSAPI, error)
	newIAM     func(ctx context.Context, region, profile string) (awsapi.IAMAPI, error)
	newQuota   func(ctx context.Context, region, profile string) (awsapi.QuotaAPI, error)
}

// load reads the config file once.
func (g *globals) load() error {
	if g.loaded != nil {
		return nil
	}
	if g.configPath == "" {
		path, err := config.DefaultPath()
		if err != nil {
			return err
		}
		g.configPath = path
	}
	cfg, found, err := config.Load(g.configPath)
	if err != nil {
		return err
	}
	g.loaded, g.found = cfg, found
	return nil
}

// orgContext returns the selected context.
//
// A missing config file is not an error: automat runs unconfigured in STANDALONE
// and MANAGEMENT, where everything it needs is discoverable. So this returns a
// zero context rather than failing, and each command decides for itself which
// fields it cannot do without.
func (g *globals) orgContext() (config.Context, error) {
	if err := g.load(); err != nil {
		return config.Context{}, err
	}
	if len(g.loaded.Contexts) == 0 {
		return config.Context{}, nil
	}
	return g.loaded.Context(g.contextName)
}

// awsConfig resolves credentials through the standard chain. This is the only
// place automat obtains credentials, and it obtains them the way every other AWS
// tool on the machine does.
func (g *globals) awsConfig(ctx context.Context, region, profile string) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("resolve AWS credentials: %w\n"+
			"automat reads the standard AWS credential chain — a profile, environment "+
			"variables, an instance or task role, or an SSO session. Run `automat login` for the "+
			"SSO device flow, or set AWS_PROFILE", err)
	}
	return cfg, nil
}

func (g *globals) ssooidcClient(ctx context.Context, region string) (awsapi.SSOOIDCAPI, error) {
	if g.newSSOOIDC != nil {
		return g.newSSOOIDC(ctx, region)
	}
	// Deliberately no profile: the device flow is how an operator gets
	// credentials, so it must work when none resolve yet. RegisterClient and
	// StartDeviceAuthorization are unauthenticated.
	cfg, err := g.awsConfig(ctx, region, "")
	if err != nil {
		return nil, err
	}
	return ssooidc.NewFromConfig(cfg), nil
}

func (g *globals) orgClient(ctx context.Context, region, profile string) (awsapi.OrgAPI, error) {
	if g.newOrg != nil {
		return g.newOrg(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
}

func (g *globals) stsClient(ctx context.Context, region, profile string) (awsapi.STSAPI, error) {
	if g.newSTS != nil {
		return g.newSTS(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return sts.NewFromConfig(cfg), nil
}

func (g *globals) iamClient(ctx context.Context, region, profile string) (awsapi.IAMAPI, error) {
	if g.newIAM != nil {
		return g.newIAM(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(cfg), nil
}

func (g *globals) quotaClient(ctx context.Context, region, profile string) (awsapi.QuotaAPI, error) {
	if g.newQuota != nil {
		return g.newQuota(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return servicequotas.NewFromConfig(cfg), nil
}
