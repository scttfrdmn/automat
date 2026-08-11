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
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/broker"
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
	newSSOOIDC    func(ctx context.Context, region string) (awsapi.SSOOIDCAPI, error)
	newOrg        func(ctx context.Context, region, profile string) (awsapi.OrgAPI, error)
	newOrgInit    func(ctx context.Context, region, profile string) (awsapi.OrgInitAPI, error)
	newOrgVend    func(ctx context.Context, region, profile string) (awsapi.OrgVendAPI, error)
	newOrgPolicy  func(ctx context.Context, region, profile string) (awsapi.OrgPolicyAPI, error)
	newOrgSetup   func(ctx context.Context, region, profile string) (awsapi.OrgSetupAPI, error)
	newOrgVerify  func(ctx context.Context, region, profile string) (awsapi.OrgVerifyAPI, error)
	newOrgReclaim func(ctx context.Context, region, profile string) (awsapi.OrgReclaimAPI, error)
	newSTS        func(ctx context.Context, region, profile string) (awsapi.STSAPI, error)
	newIAM        func(ctx context.Context, region, profile string) (awsapi.IAMAPI, error)
	newIAMRole    func(ctx context.Context, region, profile string) (awsapi.IAMRoleAPI, error)
	newQuota      func(ctx context.Context, region, profile string) (awsapi.QuotaAPI, error)
	newKMS        func(ctx context.Context, region, profile string) (awsapi.KMSAPI, error)
	// newBrokeredOrgVend overrides brokeredOrgVendClient in tests, the same way
	// every other constructor field does — a test substitutes internal/awsfake
	// here too, never a live AssumeRole.
	newBrokeredOrgVend func(ctx context.Context, region, profile, roleARN, externalIDRef string) (awsapi.OrgVendAPI, error)
	// newBrokeredOrgReclaim is brokeredOrgReclaimClient's test seam — reclaim's
	// CloseAccount half needs the vendor role in MEMBER, the same shape
	// newBrokeredOrgVend gives CreateAccount (docs/reclaim-design.md).
	newBrokeredOrgReclaim func(ctx context.Context, region, profile, roleARN, externalIDRef string) (awsapi.OrgReclaimAPI, error)
	// newChildIAMRole is childIAMRoleClient's test seam — `vend`'s in-child
	// baseline step (internal/baseline.EnsureAutomationRole) needs an IAM
	// client built from a session assumed INTO the just-vended account, the
	// same shape newBrokeredOrgVend gives a session assumed into the
	// MANAGEMENT account, but with no ExternalId: DESIGN §3 fact 6's
	// OrganizationAccountAccessRole trusts the management account outright.
	newChildIAMRole func(ctx context.Context, region, profile, partition, accountID,
		roleName string) (awsapi.IAMRoleAPI, error)

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

// orgVendClient is the account-and-OU client for MANAGEMENT and STANDALONE,
// where it is the caller's own credentials.
//
// `automat init` always calls this one: STANDALONE and MANAGEMENT are the only
// states init runs in, so it never needs the brokered constructor below.
// brokeredOrgVendClient is the MEMBER-state counterpart (DESIGN §5); `vend` picks
// between the two once it has classified the org, which is a different
// constructor at the call site rather than a branch inside either one.
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

// brokeredOrgVendClient is the account-and-OU client for the MEMBER state:
// account creation and OU creation cannot be delegated to a member account at
// all (DESIGN §3, facts 1–2), so this borrows an identity in the management
// account through the assumed vendor role instead (DESIGN §5).
//
// Never called for policy operations — those run as the caller's own delegated
// identity in every state, which is why there is no brokered counterpart to
// orgPolicyClient.
func (g *globals) brokeredOrgVendClient(ctx context.Context, region, profile, roleARN,
	externalIDRef string) (awsapi.OrgVendAPI, error) {
	if g.newBrokeredOrgVend != nil {
		return g.newBrokeredOrgVend(ctx, region, profile, roleARN, externalIDRef)
	}
	stsAPI, err := g.stsClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	cfg, err := broker.Assume(ctx, stsAPI, roleARN, externalIDRef, region)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
}

// orgPolicyClient is the service control policy client, in every state.
//
// A different constructor from orgVendClient even though both return a plain
// Organizations client here, because in the MEMBER state orgVendClient's brokered
// sibling does not: policy operations run as the caller's own delegated identity
// while account and OU operations travel through the assumed vendor role
// (DESIGN §5, brokeredOrgVendClient above). There is no brokered orgPolicyClient
// because there is nothing for one to do — the policy half never brokers.
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

// orgSetupClient is the resource-policy client `automat setup`'s MANAGEMENT-side
// apply uses, and no other command calls it — DESIGN §5's "policy half" is
// applied once, by the same operator who runs `setup`.
func (g *globals) orgSetupClient(ctx context.Context, region, profile string) (awsapi.OrgSetupAPI, error) {
	if g.newOrgSetup != nil {
		return g.newOrgSetup(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
}

// iamRoleClient is the vendor-role client `automat setup`'s MANAGEMENT-side
// apply uses to create and ensure the role DESIGN §5's "vending half" needs.
func (g *globals) iamRoleClient(ctx context.Context, region, profile string) (awsapi.IAMRoleAPI, error) {
	if g.newIAMRole != nil {
		return g.newIAMRole(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(cfg), nil
}

// orgVerifyClient is the read-only Organizations-policy client `automat
// verify` uses to read what is attached, in every state. Read-only by
// construction (internal/awsapi.OrgVerifyAPI carries no write method), so a
// bug in verify's comparison logic cannot mutate an organization no matter
// what it does — the same discipline preflight's OrgAPI enforces for reads
// during classification.
func (g *globals) orgVerifyClient(ctx context.Context, region, profile string) (awsapi.OrgVerifyAPI, error) {
	if g.newOrgVerify != nil {
		return g.newOrgVerify(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
}

// orgReclaimClient is the caller's own credentials for `automat reclaim`'s
// DetachPolicy half — delegable at the Organizations level (DESIGN §3 fact
// 3), the same credential shape orgPolicyClient already uses for every other
// policy operation. Never brokered: DetachPolicy runs as whatever identity
// is calling, native in MANAGEMENT or the caller's own delegated identity in
// MEMBER.
func (g *globals) orgReclaimClient(ctx context.Context, region, profile string) (awsapi.OrgReclaimAPI, error) {
	if g.newOrgReclaim != nil {
		return g.newOrgReclaim(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
}

// childIAMRoleClient assumes roleName into accountID and returns an IAM
// client on that session — the credential DESIGN §7 step 5 needs for the
// in-child baseline work, and DESIGN §3 fact 6's "door for in-account
// baselining": OrganizationAccountAccessRole (or whatever
// account.role_name named at CreateAccount) trusting the management account
// by default, no ExternalId required.
//
// Built via broker.Assume, the same assumption machinery
// brokeredOrgVendClient already uses for the vendor role — but with an EMPTY
// ExternalId ref, not because this assumption is less protected (it needs
// none: the trust is to the whole management account, not to a member
// account across an organization boundary) but because
// OrganizationAccountAccessRole's trust policy, as AWS creates it, names no
// condition to satisfy.
//
// roleName is the caller's to choose, but vend.go always passes
// envprofile.DefaultOrgAccessRole today: org.EnsureAccount does not send
// CreateAccountInput.RoleName (docs/cli-surface.md D3's documented gap), so
// whatever an environment profile's account.role_name says, AWS creates the
// role under its own default name regardless — and that is the name this
// client has to assume.
func (g *globals) childIAMRoleClient(ctx context.Context, region, profile, partition, accountID,
	roleName string) (awsapi.IAMRoleAPI, error) {
	if g.newChildIAMRole != nil {
		return g.newChildIAMRole(ctx, region, profile, partition, accountID, roleName)
	}
	stsAPI, err := g.stsClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	if partition == "" {
		partition = "aws"
	}
	roleARN := "arn:" + partition + ":iam::" + accountID + ":role/" + roleName
	cfg, err := broker.Assume(ctx, stsAPI, roleARN, "", region)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(cfg), nil
}

// brokeredOrgReclaimClient is CloseAccount's client for the MEMBER state:
// account closure cannot be delegated to a member account at all (same class
// as CreateAccount, DESIGN §3 facts 1-2), so this borrows an identity in the
// management account through the assumed vendor role — the same shape
// brokeredOrgVendClient already gives CreateAccount (docs/reclaim-design.md).
func (g *globals) brokeredOrgReclaimClient(ctx context.Context, region, profile, roleARN,
	externalIDRef string) (awsapi.OrgReclaimAPI, error) {
	if g.newBrokeredOrgReclaim != nil {
		return g.newBrokeredOrgReclaim(ctx, region, profile, roleARN, externalIDRef)
	}
	stsAPI, err := g.stsClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	cfg, err := broker.Assume(ctx, stsAPI, roleARN, externalIDRef, region)
	if err != nil {
		return nil, err
	}
	return organizations.NewFromConfig(cfg), nil
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

// kmsClient is evidence signing's client, native in every state: signing is
// an operation on a key the operator's own identity is granted against,
// never brokered through the vendor role (DESIGN §11's KMS drop-in has
// nothing to do with the vend/policy credential split).
func (g *globals) kmsClient(ctx context.Context, region, profile string) (awsapi.KMSAPI, error) {
	if g.newKMS != nil {
		return g.newKMS(ctx, region, profile)
	}
	cfg, err := g.awsConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(cfg), nil
}
