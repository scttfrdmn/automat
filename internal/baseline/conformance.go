// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/org"
)

// maxConformancePackInputParameters is PutConformancePackInput's own
// documented ceiling for ConformancePackInputParameters (API_PutConformancePack's
// own doc: "Array Members: Minimum number of 0 items. Maximum number of 60
// items"). Checked at render time — a plan-time refusal naming the ceiling —
// rather than left to surface as an opaque CREATE_FAILED reason string deep
// in an async CloudFormation deployment an operator cannot see until an
// apply has already assumed into the account.
const maxConformancePackInputParameters = 60

// RenderConformancePackTemplate translates a merged control set's resolved
// Config-rule map — compilesets.Merged.SortedConfigRules(), ROADMAP.md's
// "internal/baseline, slices 2-9" item 4's own naming of that method as the
// slice's whole reason for existing — into an AWS Config conformance-pack
// template body plus the parameter values that must accompany it, following
// the exact Parameters+Ref shape AWS's own hand-authoring guide
// (docs/config/latest/developerguide/custom-conformance-pack.html) and every
// published sample conformance pack use.
//
// # Why the resolved VALUES travel as ConformancePackInputParameters, not baked into the template body
//
// This is the one design decision the whole method exists to make correctly,
// because it decides whether EnsureConformancePack can ever detect drift at
// all. DescribeConformancePacks's response (ConformancePackDetail) carries no
// TemplateBody field — AWS Config does not hand the deployed template text
// back to a caller — but it DOES carry ConformancePackInputParameters, the
// exact list PutConformancePack was last called with
// (API_ConformancePackDetail's own field list). A template that inlined each
// RuleParameter's resolved value directly into InputParameters would be
// undetectable-drift by construction: there would be nothing to read back
// and compare against a later re-render. Declaring one CloudFormation
// Parameter per (rule, parameter) pair instead — Ref'd from the Resource's
// InputParameters, precisely AWS's own worked examples' own convention — and
// supplying the resolved values through ConformancePackInputParameters
// instead of Default moves the only thing that ordinarily changes between
// two vends (a catalog version bump, an override file, DESIGN §9's union
// recomputing a resolved value) into the one place AWS Config actually
// echoes back. The TEMPLATE ITSELF then only changes when the SET of rules
// or parameter NAMES changes — a catalog restructuring, not an ordinary
// re-vend — which is a rarer and cheaper case to leave undetected.
//
// # Why YAML, and why hand-rolled rather than a library
//
// PutConformancePackInput.TemplateBody's own doc comment states the two
// resource types a conformance-pack template may declare
// (AWS::Config::ConfigRule and AWS::Config::RemediationConfiguration) and
// says "you can use a YAML template" — every AWS conformance-pack sample and
// every hand-authoring guide is YAML, never JSON, unlike a plain
// CloudFormation template which documents both formats. This function
// renders YAML only, for that reason: an untested JSON path would be
// guessing at behavior nothing AWS-published states.
//
// Hand-rolled rather than built with a YAML marshaling library, mirroring
// internal/bundle's own reasoning for vendor-role.cfn.yaml
// (internal/bundle/role.go's doc comment): a struct marshaled by a generic
// encoder cannot have a value close a mapping early or open a new key,
// whatever the value contains, but a Config rule's SourceIdentifier and
// parameter names come from a catalog file — attacker-controlled input in
// this project's threat model (CLAUDE.md rule 8's own reasoning) — and this
// project has already chosen, for the sibling case of vendor-role.cfn.yaml,
// to keep template rendering a small enough hand-written function that every
// line is reviewable rather than delegated to a library's escaping rules.
// automat carries no YAML dependency today, and this function does not
// change that.
//
// # What is deliberately absent from the rendered template
//
// No Scope block: MergedConfigRule.ResourceTypes exists for its own doc
// comment's stated reason ("informational only... nothing evaluates it"),
// and DESIGN §9's union computes it by set-union across every artifact that
// bound the rule — which is the right answer for provenance but not
// necessarily the right answer for which resources should trigger an
// evaluation, a question this slice does not attempt to settle. Every
// managed rule in catalogs/cmmc-l1.json evaluates the resource types its own
// SourceIdentifier is documented against regardless of Scope (Scope only
// narrows further), so omitting it is the same "no union box automat is not
// ready to own" caution renderCondition's own doc comment names for a
// different field.
//
// No remediation actions: this project builds no auto-remediation surface at
// all (awsapi.ConfigAPI's own doc comment: "DESIGN.md's non-goals are
// explicit"), so nothing here ever emits an AWS::Config::RemediationConfiguration
// resource.
//
// # Logical IDs
//
// CloudFormation requires a logical ID be alphanumeric
// (AWSCloudFormation/latest/UserGuide/resources-section-structure.html:
// "These names must be alphanumeric (A-Za-z0-9)"), for both a Resource and a
// Parameter. A Config managed-rule identifier is validated by
// schema/control-artifact-v1.schema.json's own `^[A-Z0-9_]+$` pattern, so the
// one character it may carry that CloudFormation forbids is the underscore;
// logicalID strips it. A rule's parameter names carry no character-class
// pattern in that schema (config_rule_parameter constrains "value" and
// "order", never the object key naming the parameter), so paramLogicalID
// strips every non-alphanumeric byte rather than assuming catalog authors
// only ever choose AWS's own camelCase convention. Both stripping functions
// are followed by a collision check refusing to render rather than silently
// dropping one of two rules or parameters that stripped to the same id.
func RenderConformancePackTemplate(rules []*compilesets.MergedConfigRule) (
	templateBody string, inputParams []configtypes.ConformancePackInputParameter, err error) {
	if len(rules) == 0 {
		return "", nil, fmt.Errorf("cannot render a conformance-pack template with no Config rules: " +
			"a template with an empty Resources map is not a document AWS Config will accept, and a " +
			"caller with nothing to deploy should not call EnsureConformancePack at all")
	}

	var params strings.Builder
	var resources strings.Builder
	seenRuleIDs := make(map[string]string, len(rules))
	seenParamNames := make(map[string]string)

	for _, r := range rules {
		if r == nil || r.Identifier == "" {
			return "", nil, fmt.Errorf("cannot render a conformance-pack template: a Config rule with " +
				"no identifier reached the renderer, which should be impossible for a merge that " +
				"passed validation")
		}
		ruleID := logicalID(r.Identifier)
		if prior, dup := seenRuleIDs[ruleID]; dup {
			return "", nil, fmt.Errorf("cannot render a conformance-pack template: %q and %q both "+
				"produce the logical resource id %q, which CloudFormation requires to be unique "+
				"within one template", prior, r.Identifier, ruleID)
		}
		seenRuleIDs[ruleID] = r.Identifier

		fmt.Fprintf(&resources, "  %s:\n", ruleID)
		resources.WriteString("    Type: AWS::Config::ConfigRule\n")
		resources.WriteString("    Properties:\n")
		fmt.Fprintf(&resources, "      ConfigRuleName: %s\n",
			yamlQuote(strings.ToLower(strings.ReplaceAll(r.Identifier, "_", "-"))))
		resources.WriteString("      Source:\n")
		resources.WriteString("        Owner: AWS\n")
		fmt.Fprintf(&resources, "        SourceIdentifier: %s\n", yamlQuote(r.Identifier))

		names := make([]string, 0, len(r.Parameters))
		for name := range r.Parameters {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > 0 {
			resources.WriteString("      InputParameters:\n")
		}
		for _, name := range names {
			if name == "" {
				return "", nil, fmt.Errorf("cannot render conformance-pack rule %s: it binds a "+
					"parameter with no name, which should be impossible for a merge that passed "+
					"validation", r.Identifier)
			}
			paramID := ruleID + "Param" + paramLogicalID(name)
			if prior, dup := seenParamNames[paramID]; dup {
				return "", nil, fmt.Errorf("cannot render a conformance-pack template: %q and %q "+
					"both produce the CloudFormation parameter id %q, which must be unique within "+
					"one template", prior, r.Identifier+"."+name, paramID)
			}
			seenParamNames[paramID] = r.Identifier + "." + name

			fmt.Fprintf(&params, "  %s:\n", paramID)
			params.WriteString("    Type: String\n")

			fmt.Fprintf(&resources, "        %s:\n", yamlQuote(name))
			fmt.Fprintf(&resources, "          Ref: %s\n", paramID)

			inputParams = append(inputParams, configtypes.ConformancePackInputParameter{
				ParameterName:  aws.String(paramID),
				ParameterValue: aws.String(r.Parameters[name].Value),
			})
		}
	}

	if len(inputParams) > maxConformancePackInputParameters {
		return "", nil, fmt.Errorf("this vend's compiled control sets resolve %d Config-rule "+
			"parameters, but PutConformancePack accepts at most %d ConformancePackInputParameter "+
			"entries. automat cannot deploy a conformance pack from this control set as compiled; "+
			"narrowing the control sets or removing a rule binding is the only remedy",
			len(inputParams), maxConformancePackInputParameters)
	}

	var b strings.Builder
	b.WriteString("AWSTemplateFormatVersion: '2010-09-09'\n")
	b.WriteString("Description: >-\n")
	b.WriteString("  Conformance pack rendered by automat from the vended account's compiled\n")
	b.WriteString("  Config-rule set (DESIGN §9's union of every control set the environment\n")
	b.WriteString("  profile names). Do not hand-edit: the next vend or verify recomputes this\n")
	b.WriteString("  document from the control artifacts and overwrites it if it differs.\n")
	if params.Len() > 0 {
		b.WriteString("Parameters:\n")
		b.WriteString(params.String())
	}
	b.WriteString("Resources:\n")
	b.WriteString(resources.String())
	return b.String(), inputParams, nil
}

// logicalID derives a CloudFormation-legal logical resource ID from a Config
// managed-rule identifier. See RenderConformancePackTemplate's own "Logical
// IDs" section.
func logicalID(identifier string) string {
	return strings.ReplaceAll(identifier, "_", "")
}

// paramLogicalID derives a CloudFormation-legal fragment from a rule
// parameter's name, for concatenation into a Parameters-block logical id.
// Strips every byte outside A-Za-z0-9 rather than trusting a catalog
// author's naming convention, since schema/control-artifact-v1.schema.json
// carries no character-class pattern on a parameter's object key. See
// RenderConformancePackTemplate's own "Logical IDs" section.
func paramLogicalID(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// yamlQuote renders s as a single-quoted YAML scalar, the same discipline
// internal/bundle/role.go applies to every value substituted into
// vendor-role.cfn.yaml and for the identical reason (that file's own doc
// comment on RoleName): YAML 1.1 resolves an UNQUOTED plain scalar by
// content, so a value that happened to read as "off", "no", "true", or
// "null" would arrive at CloudFormation as a boolean or null rather than the
// string this function means to write. Single-quote escaping in YAML
// doubles an embedded quote.
func yamlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// EnsureConformancePack makes packName exist in AWS Config with templateBody
// as its deployed template and inputParams as its deployed parameter
// values — the first production consumer of
// compilesets.Merged.SortedConfigRules() (ROADMAP.md's "internal/baseline,
// slices 2-9" item 4) and the point docs/open-questions.md Q22 names as
// where an override's widened Config-rule value stops being inert: once this
// method runs, that value is a parameter of a live detective control rather
// than text in a compile-time warning.
//
// Read-first via DescribeConformancePacks, matching every other Ensure*
// method in this codebase (EnsureAutomationRole's own doc: "the same shape
// org.EnsureVendorRole uses"). PutConformancePack is called when the pack is
// absent, or present with a deployed ConformancePackInputParameters set that
// differs from inputParams — see sameInputParameters for why THAT
// comparison, rather than a template-body comparison, is the drift check
// this method can actually make (RenderConformancePackTemplate's own doc
// comment explains why the template body itself is not comparable).
// PutConformancePack is asynchronous — awsapi.ConfigAPI's own doc comment:
// "a conformance pack deploys via a CloudFormation stack under the hood" —
// so a successful call is followed by a bounded poll of
// DescribeConformancePackStatus to a terminal CREATE_COMPLETE, using the
// same PollInterval/MaxPolls/Sleep fields and default values org.Ensurer's
// own poll loop (internal/org/account.go's pollCreate) established for
// DescribeCreateAccountStatus.
func (e *Ensurer) EnsureConformancePack(ctx context.Context, packName, templateBody string,
	inputParams []configtypes.ConformancePackInputParameter) (packARN string, actions []org.Action, err error) {
	if packName == "" {
		return "", nil, fmt.Errorf("cannot ensure a conformance pack with no name")
	}
	if templateBody == "" {
		return "", nil, fmt.Errorf("cannot ensure conformance pack %s with no template body", packName)
	}
	before := len(e.actions)

	out, derr := e.Config.DescribeConformancePacks(ctx, &configservice.DescribeConformancePacksInput{
		ConformancePackNames: []string{packName},
	})
	switch {
	case derr == nil:
		packARN, err = e.ensureConformancePackFound(ctx, packName, templateBody, inputParams, out)
	case isNoSuchConformancePack(derr):
		packARN, err = e.deployConformancePack(ctx, packName, templateBody, inputParams, org.VerbCreate)
	default:
		err = awsapi.Denied(derr, "config:DescribeConformancePacks", packName, e.Principal,
			configGrantSentence("config:DescribeConformancePacks", packName, e.Principal))
	}
	return packARN, append([]org.Action(nil), e.actions[before:]...), err
}

// ensureConformancePackFound handles the DescribeConformancePacks-found
// path: the pack already exists, so this compares its deployed
// ConformancePackInputParameters against inputParams and redeploys only on a
// difference — read-then-branch, the same shape EnsureAutomationRole's
// updateAutomationRole uses for the automation role's inline policy.
func (e *Ensurer) ensureConformancePackFound(ctx context.Context, packName, templateBody string,
	inputParams []configtypes.ConformancePackInputParameter,
	out *configservice.DescribeConformancePacksOutput) (string, error) {
	var detail *configtypes.ConformancePackDetail
	for i := range out.ConformancePackDetails {
		if aws.ToString(out.ConformancePackDetails[i].ConformancePackName) == packName {
			detail = &out.ConformancePackDetails[i]
			break
		}
	}
	if detail == nil {
		// DescribeConformancePacks named this pack and returned no error, but
		// no detail matching the name — should be unreachable given the
		// filtered request, but treated as "not found" rather than a nil
		// dereference, the same defensive posture EnsureAutomationRole's own
		// isNoSuchEntity branch takes for an AWS response that does not match
		// what the method just asked for.
		return e.deployConformancePack(ctx, packName, templateBody, inputParams, org.VerbCreate)
	}
	packARN := aws.ToString(detail.ConformancePackArn)

	if sameInputParameters(detail.ConformancePackInputParameters, inputParams) {
		e.record(org.Action{
			Verb: org.VerbUnchanged, Kind: "conformance pack", Name: packName, ID: packARN,
			Detail: "deployed parameters already match what this vend's compiled control sets resolve",
		})
		return packARN, nil
	}

	if e.planning() {
		e.record(org.Action{
			Verb: org.VerbUpdate, Kind: "conformance pack", Name: packName, ID: packARN,
			Detail: "deployed parameters differ from what this vend's compiled control sets resolve " +
				"and would be replaced",
		})
		return packARN, nil
	}
	return e.deployConformancePack(ctx, packName, templateBody, inputParams, org.VerbUpdate)
}

// deployConformancePack is the create/redeploy path: PutConformancePack,
// then poll DescribeConformancePackStatus to a terminal state. verb is
// recorded on success — org.VerbCreate for a pack that did not exist,
// org.VerbUpdate for one whose parameters had drifted — since
// PutConformancePack is the identical call either way (its own doc:
// "idempotent... won't create a duplicate resource if one was already
// created") and only the caller's own read distinguishes which happened.
func (e *Ensurer) deployConformancePack(ctx context.Context, packName, templateBody string,
	inputParams []configtypes.ConformancePackInputParameter, verb org.Verb) (string, error) {
	if e.planning() {
		e.record(org.Action{
			Verb: verb, Kind: "conformance pack", Name: packName,
			Detail: "would be deployed from the compiled control sets' Config-rule set; the ARN is " +
				"assigned by AWS at creation and cannot be predicted",
		})
		return "", nil
	}

	out, err := e.Config.PutConformancePack(ctx, &configservice.PutConformancePackInput{
		ConformancePackName:            aws.String(packName),
		TemplateBody:                   aws.String(templateBody),
		ConformancePackInputParameters: inputParams,
	})
	if err != nil {
		if awsapi.IsAccessDenied(err) {
			return "", awsapi.Denied(err, "config:PutConformancePack", packName, e.Principal,
				"if baseline-protection is attached to this account's organizational unit, its "+
					"BP.CFG-3 control denies config:PutConformancePack to every principal in the "+
					"account except automat's own automation role — this session is "+
					"OrganizationAccountAccessRole, not that role, so it is denied even on a first "+
					"deploy if baseline-protection is already attached (the same Q13 ordering "+
					"docs/open-questions.md records for the automation role's own re-permissioning) "+
					"— detach baseline-protection from the OU, apply this deployment, then re-attach "+
					"baseline-protection; if baseline-protection is NOT attached to this OU, grant "+
					"config:PutConformancePack on "+packName+" to "+principalOr(e.Principal)+
					" instead. AWS does not distinguish the two causes, so both are stated")
		}
		return "", awsapi.Denied(err, "config:PutConformancePack", packName, e.Principal,
			configGrantSentence("config:PutConformancePack", packName, e.Principal))
	}
	packARN := aws.ToString(out.ConformancePackArn)

	if err := e.pollConformancePackStatus(ctx, packName); err != nil {
		return packARN, err
	}

	detail := "deployed from the compiled control sets' Config-rule set"
	if verb == org.VerbUpdate {
		detail = "redeployed: the compiled control sets now resolve different Config-rule parameters " +
			"than what was deployed"
	}
	e.record(org.Action{
		Verb: verb, Kind: "conformance pack", Name: packName, ID: packARN,
		Detail: detail, Applied: true,
	})
	return packARN, nil
}

// sameInputParameters reports whether a and b name the same
// (ParameterName, ParameterValue) pairs, order-independent — the only drift
// check EnsureConformancePack can perform, since AWS Config's
// DescribeConformancePacks never returns the deployed template text (see
// RenderConformancePackTemplate's own doc comment). Every
// ConformancePackInputParameter this package builds has a non-nil name and
// value (RenderConformancePackTemplate never appends one with either empty),
// so a nil pointer read back from AWS is treated as an empty string rather
// than risking a panic on a response shape this package does not control.
func sameInputParameters(a, b []configtypes.ConformancePackInputParameter) bool {
	if len(a) != len(b) {
		return false
	}
	toMap := func(params []configtypes.ConformancePackInputParameter) map[string]string {
		m := make(map[string]string, len(params))
		for _, p := range params {
			m[aws.ToString(p.ParameterName)] = aws.ToString(p.ParameterValue)
		}
		return m
	}
	am, bm := toMap(a), toMap(b)
	if len(am) != len(bm) {
		// Two entries in the same list shared a ParameterName — AWS would
		// reject that at PutConformancePack, but treated as "different"
		// here rather than comparing map lengths and getting lucky.
		return false
	}
	for k, v := range am {
		if bm[k] != v {
			return false
		}
	}
	return true
}

// SameInputParameters reports whether a and b name the same
// (ParameterName, ParameterValue) pairs, order-independent — exported
// wrapper around sameInputParameters for internal/verify's detective layer,
// which needs the IDENTICAL comparison EnsureConformancePack itself uses to
// decide "matches" vs. "drifted" (see that function's own doc comment for
// why this order-independent parameter comparison is the only drift check
// possible at all), not a second, possibly-diverging reimplementation of it.
func SameInputParameters(a, b []configtypes.ConformancePackInputParameter) bool {
	return sameInputParameters(a, b)
}

// pollConformancePackStatus waits for packName's async deployment
// (PutConformancePack's own doc: "creates... resources" via a CloudFormation
// stack under the hood, matching awsapi.ConfigAPI's own doc comment) to
// reach a terminal state, using the same bounded-poll shape
// internal/org/account.go's pollCreate establishes for
// DescribeCreateAccountStatus: a fixed interval, a fixed maximum number of
// polls, and a plain error on either a reported failure or exhausting the
// bound.
//
// CREATE_FAILED is the only terminal-failure ConformancePackState AWS
// documents (API_ConformancePackStatusDetail's enum also carries
// DELETE_IN_PROGRESS/DELETE_FAILED, which this method never sees on the
// create/redeploy path this package calls it from, and no UPDATE_* value at
// all — a redeploy that changes parameters reuses the same CREATE_* states)
// — ConformancePackStatusReason, when AWS populates it, is folded into the
// error text so an operator reading a parked vend's cause sees AWS's own
// explanation rather than a bare "failed".
func (e *Ensurer) pollConformancePackStatus(ctx context.Context, packName string) error {
	interval := e.pollInterval()
	for i := 0; i < e.maxPolls(); i++ {
		out, err := e.Config.DescribeConformancePackStatus(ctx,
			&configservice.DescribeConformancePackStatusInput{ConformancePackNames: []string{packName}})
		if err != nil {
			return awsapi.Denied(err, "config:DescribeConformancePackStatus", packName, e.Principal,
				configGrantSentence("config:DescribeConformancePackStatus", packName, e.Principal))
		}
		var detail *configtypes.ConformancePackStatusDetail
		for i := range out.ConformancePackStatusDetails {
			if aws.ToString(out.ConformancePackStatusDetails[i].ConformancePackName) == packName {
				detail = &out.ConformancePackStatusDetails[i]
				break
			}
		}
		if detail == nil {
			return fmt.Errorf("polling conformance pack %s's deployment status: AWS Config reported no "+
				"status for a pack this call just deployed, which should be impossible; re-run to "+
				"check again", packName)
		}
		switch detail.ConformancePackState {
		case configtypes.ConformancePackStateCreateComplete:
			return nil
		case configtypes.ConformancePackStateCreateFailed:
			reason := aws.ToString(detail.ConformancePackStatusReason)
			if reason == "" {
				reason = "AWS Config reported no reason"
			}
			return fmt.Errorf("conformance pack %s failed to deploy: %s. This is very often a "+
				"template naming an AWS Config managed rule against a resource type or region that "+
				"does not support it, or a rule identifier that no longer exists — check the reason "+
				"above against the rule identifiers this vend's control sets compiled", packName, reason)
		}
		if err := e.sleep(ctx, interval); err != nil {
			return fmt.Errorf("waiting for conformance pack %s to finish deploying: %w — the deployment "+
				"is still in flight at AWS and may yet succeed; re-run to check its status again rather "+
				"than deploying a second time", packName, err)
		}
	}
	return fmt.Errorf("conformance pack %s did not finish deploying within %s. The deployment is still "+
		"in flight at AWS and may yet succeed; re-run to check its status again rather than deploying "+
		"a second time", packName, time.Duration(e.maxPolls())*interval)
}

// isNoSuchConformancePack reports whether err is AWS Config's own "you asked
// about a pack that does not exist" signal — DescribeConformancePacks'
// documented error for a named pack that is absent, the exact parallel
// EnsureAutomationRole's isNoSuchEntity draws for IAM's GetRole.
func isNoSuchConformancePack(err error) bool {
	return awsapi.APIErrorCode(err) == "NoSuchConformancePackException"
}

// configGrantSentence is EnsureConformancePack's ORDINARY (non-Q13)
// remediation text, for the calls BP.CFG-3 (catalogs/baseline-protection.json)
// does not deny at all: DescribeConformancePacks and
// DescribeConformancePackStatus are reads, and BP.CFG-3 denies only
// config:DeleteConformancePack and config:PutConformancePack. A denial on
// either read call is therefore always an ordinary missing grant, never
// baseline-protection doing its job — grantSentence's own wording is reused
// rather than duplicated for that reason.
//
// PutConformancePack does NOT use this helper. Unlike
// EnsureAutomationRole's iam:CreateRole/iam:TagRole (absent from BP.IAM-1's
// deny list, so only a re-permissioning denial can be Q13), BP.CFG-3 denies
// config:PutConformancePack unconditionally — on the very first deploy, not
// only a later redeploy — because this session is always the assumed
// OrganizationAccountAccessRole (internal/baseline's package doc: "every
// operation THIS package performs... always runs through" it), never
// automat:automation-role, the one principal BP.CFG-3's own exemption
// names. So EVERY PutConformancePack denial may be Q13's scenario, on an
// account whose baseline-protection was already attached by an earlier
// vend or by adoption — deployConformancePack constructs that two-reading
// remediation directly, the same way updateAutomationRole
// (automation.go) constructs its own Q13 text inline rather than through a
// shared helper.
func configGrantSentence(action, resource, principal string) string {
	return grantSentence(action, resource, principal)
}
