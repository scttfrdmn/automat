// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/org"
)

const testPackName = "automat-research-cui"

// oneRule builds a single-parameter MergedConfigRule fixture, the detective
// half's equivalent of what configrules_test.go's artifactWithConfigRule
// gives the compilesets package's own tests.
func oneRule(identifier string, params map[string]artifact.RuleParameter) *compilesets.MergedConfigRule {
	return &compilesets.MergedConfigRule{Identifier: identifier, Parameters: params}
}

// TestRenderConformancePackTemplateRefusesEmpty confirms the plan-time
// refusal for a caller with nothing to deploy.
func TestRenderConformancePackTemplateRefusesEmpty(t *testing.T) {
	if _, _, err := RenderConformancePackTemplate(nil); err == nil {
		t.Fatal("want an error rendering a template with no Config rules")
	}
}

// TestRenderConformancePackTemplateShape checks the rendered YAML names the
// rule's Source and Owner correctly and Refs a Parameter rather than
// inlining the resolved value, which is the property EnsureConformancePack's
// drift detection depends on (see RenderConformancePackTemplate's own doc
// comment).
func TestRenderConformancePackTemplateShape(t *testing.T) {
	rules := []*compilesets.MergedConfigRule{
		oneRule("IAM_PASSWORD_POLICY", map[string]artifact.RuleParameter{
			"MinimumPasswordLength": {Value: "14", Order: artifact.OrderMax},
		}),
	}
	body, params, err := RenderConformancePackTemplate(rules)
	if err != nil {
		t.Fatalf("RenderConformancePackTemplate: %v", err)
	}
	if !strings.Contains(body, "AWS::Config::ConfigRule") {
		t.Errorf("template does not declare an AWS::Config::ConfigRule resource:\n%s", body)
	}
	if !strings.Contains(body, "SourceIdentifier: 'IAM_PASSWORD_POLICY'") {
		t.Errorf("template does not name the rule's SourceIdentifier:\n%s", body)
	}
	if !strings.Contains(body, "ConfigRuleName: 'iam-password-policy'") {
		t.Errorf("template does not derive the deployed rule name from the identifier:\n%s", body)
	}
	if strings.Contains(body, "'14'") {
		t.Errorf("template inlines the resolved value '14' directly, defeating drift detection:\n%s", body)
	}
	if !strings.Contains(body, "Parameters:") {
		t.Errorf("template carries no Parameters section:\n%s", body)
	}
	if !strings.Contains(body, "Ref:") {
		t.Errorf("template's InputParameters does not Ref a Parameter:\n%s", body)
	}
	if len(params) != 1 {
		t.Fatalf("want 1 ConformancePackInputParameter, got %d: %+v", len(params), params)
	}
	if got := aws.ToString(params[0].ParameterValue); got != "14" {
		t.Errorf("ConformancePackInputParameters carries value %q, want 14", got)
	}
}

// TestRenderConformancePackTemplateIsDeterministic pins the property
// EnsureConformancePack's own idempotent-re-run test depends on: two
// renders of the same input produce byte-identical template bodies and
// identically-valued (if not necessarily identically-ordered, since this
// checks values by content) input parameters. A non-deterministic render —
// map iteration order leaking into either output — would make every re-vend
// look like drift.
func TestRenderConformancePackTemplateIsDeterministic(t *testing.T) {
	rules := []*compilesets.MergedConfigRule{
		oneRule("IAM_PASSWORD_POLICY", map[string]artifact.RuleParameter{
			"MinimumPasswordLength":      {Value: "14", Order: artifact.OrderMax},
			"RequireSymbols":             {Value: "true", Order: artifact.OrderExact},
			"RequireUppercaseCharacters": {Value: "true", Order: artifact.OrderExact},
		}),
		oneRule("RESTRICTED_INCOMING_TRAFFIC", map[string]artifact.RuleParameter{
			"blockedPort1": {Value: "20", Order: artifact.OrderSetUnion},
			"blockedPort2": {Value: "21", Order: artifact.OrderSetUnion},
		}),
	}
	body1, params1, err := RenderConformancePackTemplate(rules)
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	body2, params2, err := RenderConformancePackTemplate(rules)
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	if body1 != body2 {
		t.Errorf("template body is not deterministic:\n--- first ---\n%s\n--- second ---\n%s", body1, body2)
	}
	if !sameInputParameters(params1, params2) {
		t.Errorf("input parameters are not deterministic: %+v vs %+v", params1, params2)
	}
}

// TestRenderConformancePackTemplateRefusesDuplicateLogicalID confirms two
// rules that would collide on their stripped logical resource id are
// refused rather than silently overwriting one resource with another —
// unreachable through a schema-valid identifier today
// (schema/control-artifact-v1.schema.json's `^[A-Z0-9_]+$` pattern gives no
// two distinct valid identifiers the same stripped form), but the check is
// exercised directly here since a hand-built fixture can still construct it.
func TestRenderConformancePackTemplateRefusesDuplicateLogicalID(t *testing.T) {
	rules := []*compilesets.MergedConfigRule{
		oneRule("AB_CD", nil),
		oneRule("ABCD", nil),
	}
	if _, _, err := RenderConformancePackTemplate(rules); err == nil {
		t.Fatal("want an error for two rules colliding on the same logical resource id")
	}
}

// TestRenderConformancePackTemplateRefusesTooManyParameters confirms the
// plan-time refusal at PutConformancePackInput's own documented ceiling of
// 60 ConformancePackInputParameter entries, rather than letting the error
// surface only as an opaque CREATE_FAILED reason after an apply has already
// assumed into the account.
func TestRenderConformancePackTemplateRefusesTooManyParameters(t *testing.T) {
	params := make(map[string]artifact.RuleParameter, maxConformancePackInputParameters+1)
	for i := 0; i < maxConformancePackInputParameters+1; i++ {
		params[itoa(i)] = artifact.RuleParameter{Value: "x", Order: artifact.OrderExact}
	}
	rules := []*compilesets.MergedConfigRule{oneRule("A_RULE", params)}
	if _, _, err := RenderConformancePackTemplate(rules); err == nil {
		t.Fatal("want an error for a rule set resolving more than 60 parameters")
	}
}

func itoa(n int) string {
	digits := []byte{}
	if n == 0 {
		digits = []byte{'0'}
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return "p" + string(digits)
}

// newConfigFixtureEnsurer builds an Ensurer with a fresh *awsfake.Config,
// mirroring newFixtureEnsurer's shape in automation_test.go. Sleep is a
// no-op so a test exercising the poll loop (StatusPollsLeft > 0) does not
// spend the real interval.
func newConfigFixtureEnsurer(mode org.Mode) (*Ensurer, *awsfake.Config) {
	cfg := awsfake.NewConfig()
	return &Ensurer{
		Config:    cfg,
		Mode:      mode,
		Principal: testAutomationPrincipal,
		Sleep:     func(context.Context, time.Duration) error { return nil },
	}, cfg
}

const testAutomationPrincipal = "arn:aws:sts::222222222222:assumed-role/OrganizationAccountAccessRole/automat-baseline"

// testTemplate and testParams are one rule's worth of rendered inputs, fixed
// so every EnsureConformancePack test below deploys the exact same thing
// unless it deliberately varies one of them.
var testTemplate, testParams = mustRender()

func mustRender() (string, []configtypes.ConformancePackInputParameter) {
	rules := []*compilesets.MergedConfigRule{
		oneRule("IAM_PASSWORD_POLICY", map[string]artifact.RuleParameter{
			"MinimumPasswordLength": {Value: "14", Order: artifact.OrderMax},
		}),
	}
	body, params, err := RenderConformancePackTemplate(rules)
	if err != nil {
		panic("mustRender: " + err.Error())
	}
	return body, params
}

// withValue returns a copy of params with every ParameterValue replaced by
// value — a test's way of building "the same parameter names, a different
// resolved value" without hand-rebuilding the whole rendered set.
func withValue(params []configtypes.ConformancePackInputParameter, value string) []configtypes.ConformancePackInputParameter {
	out := make([]configtypes.ConformancePackInputParameter, len(params))
	for i, p := range params {
		out[i] = configtypes.ConformancePackInputParameter{
			ParameterName:  p.ParameterName,
			ParameterValue: aws.String(value),
		}
	}
	return out
}

// seedDeployed writes cfg's state directly to look like a pack a PRIOR
// apply already deployed with params — bypassing PutConformancePack, since
// the real awsfake.Config's own PutConformancePack does not persist
// ConformancePackInputParameters through (it stores only Arn/Id/Name; see
// internal/awsfake/config.go). Writing the fake's exported maps directly is
// the same technique this package's own EnsureAutomationRole tests use
// (newFixtureEnsurer's sibling tests seed state through the fake's real
// write path where they can, and directly where the fake's write path does
// not carry the field a test needs).
func seedDeployed(cfg *awsfake.Config, packName string,
	params []configtypes.ConformancePackInputParameter) string {
	arn := "arn:aws:config:us-east-1:111111111111:conformance-pack/" + packName + "/cp-fake"
	cfg.ConformancePacks[packName] = configtypes.ConformancePackDetail{
		ConformancePackArn:             aws.String(arn),
		ConformancePackId:              aws.String("cp-fake"),
		ConformancePackName:            aws.String(packName),
		ConformancePackInputParameters: params,
	}
	cfg.ConformancePackStatuses[packName] = configtypes.ConformancePackStateCreateComplete
	return arn
}

// TestEnsureConformancePackPlanCreatesNothing is CLAUDE.md rule 5: a plan
// must issue no mutating call, on a first-ensure (the pack does not exist
// yet — DescribeConformancePacks returns NoSuchConformancePackException).
func TestEnsureConformancePackPlanCreatesNothing(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModePlan)

	arn, actions, err := e.EnsureConformancePack(ctx(), testPackName, testTemplate, testParams)
	if err != nil {
		t.Fatalf("EnsureConformancePack: %v", err)
	}
	if arn != "" {
		t.Errorf("a plan must not report an ARN for a pack it has not created, got %q", arn)
	}
	for _, op := range []string{"PutConformancePack", "DescribeConformancePackStatus"} {
		if n := cfg.CallCount(op); n != 0 {
			t.Errorf("plan mode called %s %d times; a plan must write nothing", op, n)
		}
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbCreate || actions[0].Applied {
		t.Fatalf("want one unapplied create action, got %+v", actions)
	}
}

// TestEnsureConformancePackApplyCreatesAndPolls is the apply-mode
// counterpart: the pack must be deployed via PutConformancePack and then
// polled to a terminal CREATE_COMPLETE before the method returns.
func TestEnsureConformancePackApplyCreatesAndPolls(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	// Two IN_PROGRESS answers before CREATE_COMPLETE, so this test actually
	// exercises the poll loop rather than completing on the first call.
	cfg.StatusPollsLeft[testPackName] = 2

	arn, actions, err := e.EnsureConformancePack(ctx(), testPackName, testTemplate, testParams)
	if err != nil {
		t.Fatalf("EnsureConformancePack: %v", err)
	}
	if arn == "" {
		t.Fatal("an applied create must report the pack's ARN")
	}
	if n := cfg.CallCount("PutConformancePack"); n != 1 {
		t.Errorf("PutConformancePack called %d times, want 1", n)
	}
	if n := cfg.CallCount("DescribeConformancePackStatus"); n != 3 {
		t.Errorf("DescribeConformancePackStatus called %d times, want 3 (2 IN_PROGRESS + 1 COMPLETE)", n)
	}
	if len(actions) != 1 || !actions[0].Applied || actions[0].Verb != org.VerbCreate {
		t.Fatalf("want one applied create action, got %+v", actions)
	}
	if cfg.ConformancePackStatuses[testPackName] != configtypes.ConformancePackStateCreateComplete {
		t.Errorf("pack status = %s, want CREATE_COMPLETE", cfg.ConformancePackStatuses[testPackName])
	}
}

// TestEnsureConformancePackIdempotent is CLAUDE.md rule 4: a second apply
// against an unchanged desired state must issue no write.
func TestEnsureConformancePackIdempotent(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	wantARN := seedDeployed(cfg, testPackName, testParams)
	cfg.Reset()

	arn, actions, err := e.EnsureConformancePack(ctx(), testPackName, testTemplate, testParams)
	if err != nil {
		t.Fatalf("EnsureConformancePack: %v", err)
	}
	if arn != wantARN {
		t.Errorf("arn = %q, want %q", arn, wantARN)
	}
	if n := cfg.CallCount("PutConformancePack"); n != 0 {
		t.Errorf("PutConformancePack called %d times; a re-run against unchanged parameters must "+
			"write nothing", n)
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbUnchanged || actions[0].Applied {
		t.Fatalf("want one unchanged, unapplied action, got %+v", actions)
	}
}

// TestEnsureConformancePackDriftTriggersUpdate is the ordinary re-vend
// case ROADMAP.md's own scope statement asks for: a pack already deployed
// with a DIFFERENT resolved Config-rule parameter than this vend's compiled
// control sets now produce (a catalog version bump, an override file, or
// DESIGN §9's union recomputing a value) must be redeployed.
func TestEnsureConformancePackDriftTriggersUpdate(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	seedDeployed(cfg, testPackName, withValue(testParams, "8"))
	cfg.Reset()

	arn, actions, err := e.EnsureConformancePack(ctx(), testPackName, testTemplate, testParams)
	if err != nil {
		t.Fatalf("EnsureConformancePack: %v", err)
	}
	if arn == "" {
		t.Error("an applied update must still report the pack's ARN")
	}
	if n := cfg.CallCount("PutConformancePack"); n != 1 {
		t.Errorf("PutConformancePack called %d times, want 1", n)
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbUpdate || !actions[0].Applied {
		t.Fatalf("want one applied update action, got %+v", actions)
	}
}

// TestEnsureConformancePackPlanOnDriftedPackReportsUpdateWithoutWriting is
// the plan-mode counterpart: drift is reported, but nothing is written.
func TestEnsureConformancePackPlanOnDriftedPackReportsUpdateWithoutWriting(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModePlan)
	arn := seedDeployed(cfg, testPackName, withValue(testParams, "8"))
	cfg.Reset()

	gotARN, actions, err := e.EnsureConformancePack(ctx(), testPackName, testTemplate, testParams)
	if err != nil {
		t.Fatalf("EnsureConformancePack: %v", err)
	}
	if gotARN != arn {
		t.Errorf("a plan against an EXISTING pack must report its ARN, got %q want %q", gotARN, arn)
	}
	if n := cfg.CallCount("PutConformancePack"); n != 0 {
		t.Errorf("plan mode called PutConformancePack %d times; a plan must write nothing", n)
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbUpdate || actions[0].Applied {
		t.Fatalf("want one unapplied update action, got %+v", actions)
	}
}

// failedStatusConfig wraps *awsfake.Config and overrides
// DescribeConformancePackStatus to report CREATE_FAILED unconditionally —
// awsfake.Config's own poll simulation (StatusPollsLeft) only ever resolves
// to CREATE_COMPLETE, so a test exercising pollConformancePackStatus's
// failure branch needs this rather than the fake alone. Every other method
// delegates straight through, so PutConformancePack, DescribeConformancePacks,
// and call-count bookkeeping all still run against the real fake.
type failedStatusConfig struct {
	*awsfake.Config
	reason string
}

func (f *failedStatusConfig) DescribeConformancePackStatus(ctx context.Context,
	in *configservice.DescribeConformancePackStatusInput, optFns ...func(*configservice.Options),
) (*configservice.DescribeConformancePackStatusOutput, error) {
	f.Record("DescribeConformancePackStatus")
	var out []configtypes.ConformancePackStatusDetail
	for _, name := range in.ConformancePackNames {
		pack, ok := f.ConformancePacks[name]
		if !ok {
			continue
		}
		out = append(out, configtypes.ConformancePackStatusDetail{
			ConformancePackArn:          pack.ConformancePackArn,
			ConformancePackId:           pack.ConformancePackId,
			ConformancePackName:         pack.ConformancePackName,
			ConformancePackState:        configtypes.ConformancePackStateCreateFailed,
			ConformancePackStatusReason: aws.String(f.reason),
			StackArn:                    aws.String("arn:aws:cloudformation:us-east-1:111111111111:stack/cp-fake/fake"),
		})
	}
	return &configservice.DescribeConformancePackStatusOutput{ConformancePackStatusDetails: out}, nil
}

// TestEnsureConformancePackFailedDeploymentSurfacesError confirms a
// CREATE_FAILED status is a clear, returned error naming AWS's own reason,
// rather than a silent success — the failure mode that would otherwise
// leave `vend`'s caller believing a conformance pack deployed when it did
// not.
func TestEnsureConformancePackFailedDeploymentSurfacesError(t *testing.T) {
	inner := awsfake.NewConfig()
	wrapped := &failedStatusConfig{Config: inner, reason: "unsupported resource type in this region"}
	e := &Ensurer{
		Config:    wrapped,
		Mode:      org.ModeApply,
		Principal: testAutomationPrincipal,
		Sleep:     func(context.Context, time.Duration) error { return nil },
	}

	_, _, err := e.EnsureConformancePack(ctx(), testPackName, testTemplate, testParams)
	if err == nil {
		t.Fatal("want an error when the conformance pack's deployment status is CREATE_FAILED")
	}
	if !strings.Contains(err.Error(), "failed to deploy") {
		t.Errorf("error does not say the deployment failed: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported resource type in this region") {
		t.Errorf("error does not carry AWS's own failure reason: %v", err)
	}
}

// TestEnsureConformancePackParksOnPutDenial is BP.CFG-3's own version of
// Q13: unlike EnsureAutomationRole's iam:CreateRole (absent from BP.IAM-1's
// deny list), BP.CFG-3 denies config:PutConformancePack unconditionally —
// even on a FIRST deploy — because this session is always the assumed
// OrganizationAccountAccessRole, never automat:automation-role, the one
// principal BP.CFG-3's own exemption names. A denial here must be an
// awsapi.PermissionError (so org.Parkable recognizes it) whose remediation
// names both the baseline-protection reading and the ordinary
// missing-grant reading, because AccessDenied alone cannot prove which
// applies — the exact shape TestEnsureAutomationRoleParksOnRePermissionDenial
// pins for the automation role.
func TestEnsureConformancePackParksOnPutDenial(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	cfg.PutConformancePackErr = awsfake.AccessDenied("config:PutConformancePack")

	_, actions, err := e.EnsureConformancePack(ctx(), testPackName, testTemplate, testParams)
	if err == nil {
		t.Fatal("want an error when PutConformancePack is denied")
	}
	if !org.Parkable(err) {
		t.Errorf("this denial must be org.Parkable so `vend` parks rather than fails outright: %v", err)
	}
	if !strings.Contains(err.Error(), "baseline-protection") {
		t.Errorf("error does not mention baseline-protection (BP.CFG-3): %v", err)
	}
	if !strings.Contains(err.Error(), "detach baseline-protection") {
		t.Errorf("error carries no remediation to detach baseline-protection: %v", err)
	}
	for _, a := range actions {
		if a.Applied {
			t.Errorf("a denied write must not be recorded as Applied: %+v", a)
		}
	}
}
