// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

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
	//
	// There is one per awsapi interface rather than one per AWS service, and the
	// three Organizations entries are not redundant. A constructor per interface is
	// what makes "this command holds no init client" a fact about the wiring rather
	// than a claim about the code, and in the MEMBER state the vend and policy
	// halves genuinely run on different credentials (DESIGN §5), so they cannot
	// share one. `automat init` is the only caller of newOrgInit, and `automat
	// vend` is the only caller of newOrgPolicy.
	newSSOOIDC   func(ctx context.Context, region string) (awsapi.SSOOIDCAPI, error)
	newOrg       func(ctx context.Context, region, profile string) (awsapi.OrgAPI, error)
	newOrgInit   func(ctx context.Context, region, profile string) (awsapi.OrgInitAPI, error)
	newOrgVend   func(ctx context.Context, region, profile string) (awsapi.OrgVendAPI, error)
	newOrgPolicy func(ctx context.Context, region, profile string) (awsapi.OrgPolicyAPI, error)
	newSTS       func(ctx context.Context, region, profile string) (awsapi.STSAPI, error)
	newIAM       func(ctx context.Context, region, profile string) (awsapi.IAMAPI, error)
	newQuota     func(ctx context.Context, region, profile string) (awsapi.QuotaAPI, error)

	// sleep is how a command waits between polls, and it is a field for the same
	// reason the constructors are. CreateAccount is asynchronous, so `vend` waits;
	// a test that waited for real would spend the poll interval per poll per case,
	// and one that shortened the interval instead would be testing a timing the
	// binary never uses. nil means org.Ensurer's own default, which is what
	// production gets.
	sleep func(ctx context.Context, d time.Duration) error
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

// orgInitClient is the organization-creation client, and only `automat init`
// calls it. The narrow interface is what keeps CreateOrganization and
// EnablePolicyType unreachable from every other command (internal/awsapi/api.go).
func (g *globals) orgInitClient(ctx context.Context, region, profile string) (awsapi.OrgInitAPI, error) {
	if g.newOrgInit != nil {
		return g.newOrgInit(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
}

// orgVendClient is the account-and-OU client.
//
// In MANAGEMENT and STANDALONE this is the caller's own credentials, which is what
// this returns. In MEMBER it must be the brokered vendor role instead (DESIGN §5),
// and that is internal/broker's job in Phase 3 — the seam is here so the change is
// a different constructor rather than a different call site.
func (g *globals) orgVendClient(ctx context.Context, region, profile string) (awsapi.OrgVendAPI, error) {
	if g.newOrgVend != nil {
		return g.newOrgVend(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
}

// orgPolicyClient is the service control policy client.
//
// A different constructor from orgVendClient even though both return an
// Organizations client today, because in the MEMBER state they will not: policy
// operations run as the caller's own delegated identity while account and OU
// operations travel through the assumed vendor role (DESIGN §5). Sharing one
// constructor would make that difference invisible at the moment Phase 3 has to
// introduce it, and the difference is the whole security argument the onboarding
// bundle makes.
func (g *globals) orgPolicyClient(ctx context.Context, region, profile string) (awsapi.OrgPolicyAPI, error) {
	if g.newOrgPolicy != nil {
		return g.newOrgPolicy(ctx, region, profile)
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
