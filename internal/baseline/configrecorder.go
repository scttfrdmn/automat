// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/org"
)

// defaultRecorderName is the name AWS Config itself assigns a customer
// managed configuration recorder created with no name
// (configtypes.ConfigurationRecorder's own doc comment: "Config automatically
// assigns the name of 'default'... if you do not specify a name at creation
// time"). envprofile.ConfigRecorder carries no name field of its own — DESIGN
// §7 step 5 names one recorder per account, not several — so this Ensurer
// always names the recorder "default" itself rather than leaving the field
// empty and letting AWS's own default apply silently; a caller must be able
// to Describe/Start the exact recorder it just Put without a second read to
// discover what AWS decided to call it. awsfake.Config's own
// PutConfigurationRecorder applies the identical substitution for an empty
// name, so a fake-backed test and a real one agree.
const defaultRecorderName = "default"

// EnsureConfigRecorder makes an AWS Config configuration recorder exist,
// carry spec's recording scope, and be actively RECORDING —
// ROADMAP.md's "internal/baseline, slices 2-9" item 3, DESIGN §7 step 5's
// remaining piece: "Deploy detective baseline: Config recorder, delivery
// channel, conformance pack..." (DESIGN §7, bullet 2). The conformance pack
// half is EnsureConformancePack (conformance.go), already built; this is the
// recorder half.
//
// A no-op, with no action recorded at all, when spec.Enabled is false: a
// profile that does not want a recorder should produce nothing to report,
// the same "true no-op" discipline vendRegionsStep's own doc comment
// describes for a profile naming no baseline.regions block.
//
// # Two actions in the common create case, not one — read EnsureSCPEnabled's
// own "created but not enabled" precedent
//
// PutConfigurationRecorder creates or replaces the recorder's configuration
// (its recording group and the role it records as) but does not turn
// recording on — awsapi.ConfigAPI's own doc comment draws the exact parallel
// to org.EnsureSCPEnabled's EnablePolicyType: "the write that makes the
// resource exist is not the write that makes it active." So this method
// always performs the read-then-branch for the recorder's configuration
// FIRST (create or update, or VerbUnchanged if it already matches spec), and
// then, independently, checks whether the recorder is actually recording and
// calls StartConfigurationRecorder if it is not — regardless of whether the
// configuration half just changed or was already correct. A recorder created
// by an out-of-band process (a hand-run `aws configservice
// put-configuration-recorder` before automat ever touched the account) and
// never started is exactly the case this second, independent check exists to
// catch: EnsureConfigRecorder must not assume "the configuration was already
// right" means "so recording must already be on".
//
// # Read-first, matching every other Ensure method in this package
//
// DescribeConfigurationRecorders, named at the one recorder this method ever
// manages (defaultRecorderName), is called before any write — the same
// discipline EnsureAutomationRole's own doc comment states ("the same shape
// org.EnsureVendorRole uses"). automationRoleARN is what PutConfigurationRecorder's
// RoleARN names: the in-account automation role established just before this
// step runs (vendAutomationRoleStep), never automat's own broker session,
// because the RECORDER's own recording activity must survive automat never
// touching this account again.
func (e *Ensurer) EnsureConfigRecorder(ctx context.Context, spec envprofile.ConfigRecorder,
	automationRoleARN string) ([]org.Action, error) {
	if e.Config == nil {
		return nil, fmt.Errorf("cannot ensure a Config recorder: this Ensurer has no Config client")
	}
	if !spec.Enabled {
		return nil, nil
	}
	if automationRoleARN == "" {
		return nil, fmt.Errorf("cannot ensure a Config recorder with no automation role ARN: " +
			"PutConfigurationRecorder requires one, and the recorder's own recording activity must " +
			"survive automat's own session ending, so it cannot record as automat's broker role")
	}
	before := len(e.actions)

	if err := e.ensureRecorderConfig(ctx, spec, automationRoleARN); err != nil {
		return append([]org.Action(nil), e.actions[before:]...), err
	}
	if err := e.ensureRecorderStarted(ctx); err != nil {
		return append([]org.Action(nil), e.actions[before:]...), err
	}
	return append([]org.Action(nil), e.actions[before:]...), nil
}

// ensureRecorderConfig is EnsureConfigRecorder's first action: create-or-
// update the recorder's own configuration (its recording group and role),
// read-then-branch against DescribeConfigurationRecorders.
func (e *Ensurer) ensureRecorderConfig(ctx context.Context, spec envprofile.ConfigRecorder, roleARN string) error {
	out, derr := e.Config.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{
		ConfigurationRecorderNames: []string{defaultRecorderName},
	})
	switch {
	case derr == nil:
		return e.ensureRecorderConfigFound(ctx, spec, roleARN, out)
	case isNoSuchConfigurationRecorder(derr):
		return e.putRecorderConfig(ctx, spec, roleARN, org.VerbCreate)
	default:
		return awsapi.Denied(derr, "config:DescribeConfigurationRecorders", defaultRecorderName, e.Principal,
			configGrantSentence("config:DescribeConfigurationRecorders", defaultRecorderName, e.Principal))
	}
}

// ensureRecorderConfigFound handles the DescribeConfigurationRecorders-found
// path: the recorder already exists, so this compares its deployed recording
// group and role against spec/roleARN and writes only on drift — the same
// read-then-branch shape EnsureAutomationRole's updateAutomationRole and
// EnsureConformancePack's ensureConformancePackFound both use.
func (e *Ensurer) ensureRecorderConfigFound(ctx context.Context, spec envprofile.ConfigRecorder,
	roleARN string, out *configservice.DescribeConfigurationRecordersOutput) error {
	var rec *configtypes.ConfigurationRecorder
	for i := range out.ConfigurationRecorders {
		if aws.ToString(out.ConfigurationRecorders[i].Name) == defaultRecorderName {
			rec = &out.ConfigurationRecorders[i]
			break
		}
	}
	if rec == nil {
		// DescribeConfigurationRecorders named this recorder and returned no
		// error, but no recorder matching the name — should be unreachable
		// given the filtered request, the same defensive posture
		// EnsureConformancePack's own doc comment takes for the identical
		// shape.
		return e.putRecorderConfig(ctx, spec, roleARN, org.VerbCreate)
	}

	if sameRecorderConfig(rec, spec, roleARN) {
		e.record(org.Action{
			Verb: org.VerbUnchanged, Kind: "Config recorder", Name: defaultRecorderName,
			ID:     aws.ToString(rec.Arn),
			Detail: "recording scope and role already match what this vend describes",
		})
		return nil
	}

	if e.planning() {
		e.record(org.Action{
			Verb: org.VerbUpdate, Kind: "Config recorder", Name: defaultRecorderName, ID: aws.ToString(rec.Arn),
			Detail: "recording scope or role differs from what this vend describes and would be replaced",
		})
		return nil
	}
	return e.putRecorderConfig(ctx, spec, roleARN, org.VerbUpdate)
}

// sameRecorderConfig reports whether rec, as deployed, already matches
// spec's recording scope and roleARN.
func sameRecorderConfig(rec *configtypes.ConfigurationRecorder, spec envprofile.ConfigRecorder, roleARN string) bool {
	if aws.ToString(rec.RoleARN) != roleARN {
		return false
	}
	if rec.RecordingGroup == nil {
		return false
	}
	return rec.RecordingGroup.AllSupported == spec.RecordsAllSupportedResources() &&
		rec.RecordingGroup.IncludeGlobalResourceTypes == spec.RecordsGlobalResourceTypes()
}

// putRecorderConfig is the create/replace path: a single PutConfigurationRecorder
// call, since — like EnsureAutomationRole's PutRolePolicy — Config's own API
// carries no separate update method (awsfake.Config's own PutConfigurationRecorder
// doc: "Create-or-replace, matching the real call").
func (e *Ensurer) putRecorderConfig(ctx context.Context, spec envprofile.ConfigRecorder,
	roleARN string, verb org.Verb) error {
	if e.planning() {
		detail := "would be created with the recording scope this vend describes"
		if verb == org.VerbUpdate {
			detail = "recording scope or role differs from what this vend describes and would be replaced"
		}
		e.record(org.Action{
			Verb: verb, Kind: "Config recorder", Name: defaultRecorderName, Detail: detail,
		})
		return nil
	}

	_, err := e.Config.PutConfigurationRecorder(ctx, &configservice.PutConfigurationRecorderInput{
		ConfigurationRecorder: &configtypes.ConfigurationRecorder{
			Name:    aws.String(defaultRecorderName),
			RoleARN: aws.String(roleARN),
			RecordingGroup: &configtypes.RecordingGroup{
				AllSupported:               spec.RecordsAllSupportedResources(),
				IncludeGlobalResourceTypes: spec.RecordsGlobalResourceTypes(),
			},
		},
	})
	if err != nil {
		return e.deniedRecorderWrite(err, "config:PutConfigurationRecorder")
	}

	detail := "created with the recording scope this vend describes"
	if verb == org.VerbUpdate {
		detail = "recording scope or role replaced to match what this vend describes"
	}
	e.record(org.Action{
		Verb: verb, Kind: "Config recorder", Name: defaultRecorderName, Detail: detail, Applied: true,
	})
	return nil
}

// ensureRecorderStarted is EnsureConfigRecorder's second, independent
// action: the recorder now exists (this call's own putRecorderConfig, an
// earlier vend's, or an out-of-band `put-configuration-recorder`) but may not
// be RECORDING — see the method doc's "created but not enabled" section.
// Reads DescribeConfigurationRecorderStatus rather than trusting
// ensureRecorderConfig's own DescribeConfigurationRecorders read, because
// that read happened before this call's own Put (if any) and cannot tell
// "exists" from "exists AND recording" either way —
// ConfigurationRecorderStatus.Recording is the one field that can, and it is
// on this call's own read, never the other one (awsapi.ConfigAPI's own doc
// comment on why the two methods exist separately).
func (e *Ensurer) ensureRecorderStarted(ctx context.Context) error {
	out, derr := e.Config.DescribeConfigurationRecorderStatus(ctx,
		&configservice.DescribeConfigurationRecorderStatusInput{ConfigurationRecorderNames: []string{defaultRecorderName}})
	if derr != nil {
		if isNoSuchConfigurationRecorder(derr) {
			// A plan that has not created the recorder yet has nothing to
			// start — the create action already reported the plan-would-
			// create detail, and there is no recorder to Start against in
			// plan mode. Reachable only when e.planning() is true, since an
			// apply's putRecorderConfig would have created one moments ago.
			if e.planning() {
				return nil
			}
			return fmt.Errorf("checking whether the Config recorder %s is recording: it does not exist "+
				"even though this apply should have just created it. Report this", defaultRecorderName)
		}
		return awsapi.Denied(derr, "config:DescribeConfigurationRecorderStatus", defaultRecorderName, e.Principal,
			configGrantSentence("config:DescribeConfigurationRecorderStatus", defaultRecorderName, e.Principal))
	}

	var status *configtypes.ConfigurationRecorderStatus
	for i := range out.ConfigurationRecordersStatus {
		if aws.ToString(out.ConfigurationRecordersStatus[i].Name) == defaultRecorderName {
			status = &out.ConfigurationRecordersStatus[i]
			break
		}
	}
	if status == nil {
		// Plan mode with nothing deployed yet: nothing to start.
		if e.planning() {
			return nil
		}
		return fmt.Errorf("checking whether the Config recorder %s is recording: "+
			"DescribeConfigurationRecorderStatus named it and returned no error, but no status matched. "+
			"Report this", defaultRecorderName)
	}

	if status.Recording {
		e.record(org.Action{
			Verb: org.VerbUnchanged, Kind: "Config recorder recording state", Name: defaultRecorderName,
			ID: aws.ToString(status.Arn), Detail: "already recording",
		})
		return nil
	}

	if e.planning() {
		e.record(org.Action{
			Verb: org.VerbEnable, Kind: "Config recorder recording state", Name: defaultRecorderName,
			ID: aws.ToString(status.Arn),
			Detail: "would be started: the recorder exists but is not currently recording — created " +
				"without being started records nothing while reporting no error",
		})
		return nil
	}

	if _, err := e.Config.StartConfigurationRecorder(ctx,
		&configservice.StartConfigurationRecorderInput{ConfigurationRecorderName: aws.String(defaultRecorderName)},
	); err != nil {
		return e.deniedRecorderWrite(err, "config:StartConfigurationRecorder")
	}
	e.record(org.Action{
		Verb: org.VerbEnable, Kind: "Config recorder recording state", Name: defaultRecorderName,
		ID: aws.ToString(status.Arn), Detail: "started", Applied: true,
	})
	return nil
}

// deniedRecorderWrite is EnsureConfigRecorder's Q13-shaped remediation for
// its two write calls (PutConfigurationRecorder, StartConfigurationRecorder).
// BP.CFG-1 (catalogs/baseline-protection.json) denies both actions to every
// principal in the account EXCEPT automat:automation-role — and this
// session, like EnsureConformancePack's own session, is always the assumed
// OrganizationAccountAccessRole, never that role (internal/baseline's
// package doc: "every operation THIS package performs... always runs
// through" it). So a denial on EITHER call may be Q13's scenario even on a
// first deploy, the same reasoning configGrantSentence's own doc comment
// gives for PutConformancePack, restated here rather than shared through one
// helper because the exempting control (BP.CFG-1, not BP.CFG-3) and the
// resource (the recorder, not a pack) differ.
func (e *Ensurer) deniedRecorderWrite(err error, action string) error {
	if awsapi.IsAccessDenied(err) {
		return awsapi.Denied(err, action, defaultRecorderName, e.Principal,
			"if baseline-protection is attached to this account's organizational unit, its BP.CFG-1 "+
				"control denies "+action+" to every principal in the account except automat's own "+
				"automation role — this session is OrganizationAccountAccessRole, not that role, so it "+
				"is denied even on a first deploy if baseline-protection is already attached (the same "+
				"Q13 ordering docs/open-questions.md records for the automation role's own "+
				"re-permissioning and the conformance pack's own deploy) — detach baseline-protection "+
				"from the OU, apply this change, then re-attach baseline-protection; if "+
				"baseline-protection is NOT attached to this OU, grant "+action+" on "+defaultRecorderName+
				" to "+principalOr(e.Principal)+" instead. AWS does not distinguish the two causes, so "+
				"both are stated")
	}
	return awsapi.Denied(err, action, defaultRecorderName, e.Principal,
		configGrantSentence(action, defaultRecorderName, e.Principal))
}

// DefaultRecorderName is the recorder (and delivery channel) name this
// package always uses — see defaultRecorderName's own doc comment. Exported
// so internal/verify's detective layer (CheckDetective, ROADMAP.md's
// "internal/baseline, slices 2-9" item 9) can Describe the exact resource
// this package ensures, without a second, possibly-diverging definition of
// "which recorder automat means" living in two packages.
const DefaultRecorderName = defaultRecorderName

// SameRecorderConfig reports whether rec, as deployed, already matches
// spec's recording scope and roleARN — exported wrapper around
// sameRecorderConfig for internal/verify's detective layer, which needs the
// IDENTICAL comparison EnsureConfigRecorder itself uses to decide "matches"
// vs. "drifted", not a second, possibly-diverging reimplementation of it.
func SameRecorderConfig(rec *configtypes.ConfigurationRecorder, spec envprofile.ConfigRecorder, roleARN string) bool {
	return sameRecorderConfig(rec, spec, roleARN)
}

// isNoSuchConfigurationRecorder reports whether err is AWS Config's own "you
// asked about a recorder that does not exist" signal — the exact parallel
// isNoSuchConformancePack draws for DescribeConformancePacks and
// isNoSuchEntity draws for IAM's GetRole.
func isNoSuchConfigurationRecorder(err error) bool {
	return awsapi.APIErrorCode(err) == "NoSuchConfigurationRecorderException"
}

// EnsureDeliveryChannel makes an AWS Config delivery channel exist, pointed
// at spec.DeliveryBucket — DESIGN §7 step 5's other new piece this slice
// builds, EnsureConfigRecorder's sibling.
//
// # Scope cut, decided by ROADMAP.md's own text, not this method's choice
//
// spec.DeliveryBucket MUST name a pre-existing, operator-named S3 bucket.
// automat does not create one: ROADMAP's own scope statement for this slice
// says so explicitly ("automat does not provision S3 buckets with their own
// lifecycle/encryption/public-access-block policy in this pass"), because a
// bucket automat both creates and never administers afterward would need
// exactly the kind of ongoing lifecycle ownership this project's non-goals
// rule out (DESIGN.md's "no continuous monitoring/evidence agents" is the
// same shape of restraint, for a different resource). So an empty
// DeliveryBucket is refused HERE, at what is effectively plan time — before
// any AWS call — naming the exact profile field that is missing, rather than
// letting PutDeliveryChannel fail on a nil S3BucketName deep in an apply.
//
// A no-op, with no action recorded at all, when spec.Enabled is false —
// EnsureConfigRecorder's own no-op convention, restated here because the two
// methods share one envprofile.ConfigRecorder spec and `vend`'s own caller
// (vendConfigRecorderStep) must be free to call both unconditionally without
// each one re-deriving "did the profile actually ask for this".
//
// Read-first via DescribeDeliveryChannels, create-or-update via
// PutDeliveryChannel on drift — EnsureConfigRecorder's own read-then-branch
// shape, restated for the delivery channel's own resource and its own
// NoSuchDeliveryChannelException read-first signal.
func (e *Ensurer) EnsureDeliveryChannel(ctx context.Context, spec envprofile.ConfigRecorder) (*org.Action, error) {
	if e.Config == nil {
		return nil, fmt.Errorf("cannot ensure a Config delivery channel: this Ensurer has no Config client")
	}
	if !spec.Enabled {
		return nil, nil
	}
	if spec.DeliveryBucket == "" {
		return nil, fmt.Errorf("baseline.config_recorder.enabled is true, but " +
			"baseline.config_recorder.delivery_bucket is empty. automat will not create an S3 bucket " +
			"for the delivery channel — the bucket needs its own lifecycle, encryption, and " +
			"public-access-block policy, which is administration this project does not take on. Create " +
			"the bucket yourself (or point at one central IT already operates) and set " +
			"baseline.config_recorder.delivery_bucket to its name")
	}

	out, derr := e.Config.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{
		DeliveryChannelNames: []string{defaultRecorderName},
	})
	switch {
	case derr == nil:
		return e.ensureDeliveryChannelFound(ctx, spec, out)
	case isNoSuchDeliveryChannel(derr):
		return e.putDeliveryChannel(ctx, spec, org.VerbCreate)
	default:
		return nil, awsapi.Denied(derr, "config:DescribeDeliveryChannels", defaultRecorderName, e.Principal,
			configGrantSentence("config:DescribeDeliveryChannels", defaultRecorderName, e.Principal))
	}
}

// ensureDeliveryChannelFound handles the DescribeDeliveryChannels-found
// path: the channel already exists, so this compares its deployed bucket
// against spec.DeliveryBucket and writes only on drift.
func (e *Ensurer) ensureDeliveryChannelFound(ctx context.Context, spec envprofile.ConfigRecorder,
	out *configservice.DescribeDeliveryChannelsOutput) (*org.Action, error) {
	var ch *configtypes.DeliveryChannel
	for i := range out.DeliveryChannels {
		if aws.ToString(out.DeliveryChannels[i].Name) == defaultRecorderName {
			ch = &out.DeliveryChannels[i]
			break
		}
	}
	if ch == nil {
		return e.putDeliveryChannel(ctx, spec, org.VerbCreate)
	}

	if aws.ToString(ch.S3BucketName) == spec.DeliveryBucket {
		a := e.record(org.Action{
			Verb: org.VerbUnchanged, Kind: "Config delivery channel", Name: defaultRecorderName,
			Detail: "already delivers to " + spec.DeliveryBucket,
		})
		return a, nil
	}

	if e.planning() {
		a := e.record(org.Action{
			Verb: org.VerbUpdate, Kind: "Config delivery channel", Name: defaultRecorderName,
			Detail: "delivers to a different bucket than this vend describes and would be repointed to " +
				spec.DeliveryBucket,
		})
		return a, nil
	}
	return e.putDeliveryChannel(ctx, spec, org.VerbUpdate)
}

// putDeliveryChannel is the create/replace path: a single PutDeliveryChannel
// call, matching the real API's own create-or-replace shape (no separate
// update method) — the exact parallel putRecorderConfig draws for
// PutConfigurationRecorder.
func (e *Ensurer) putDeliveryChannel(ctx context.Context, spec envprofile.ConfigRecorder,
	verb org.Verb) (*org.Action, error) {
	if e.planning() {
		detail := "would be created, delivering to " + spec.DeliveryBucket
		if verb == org.VerbUpdate {
			detail = "delivers to a different bucket than this vend describes and would be repointed to " +
				spec.DeliveryBucket
		}
		a := e.record(org.Action{
			Verb: verb, Kind: "Config delivery channel", Name: defaultRecorderName, Detail: detail,
		})
		return a, nil
	}

	_, err := e.Config.PutDeliveryChannel(ctx, &configservice.PutDeliveryChannelInput{
		DeliveryChannel: &configtypes.DeliveryChannel{
			Name:         aws.String(defaultRecorderName),
			S3BucketName: aws.String(spec.DeliveryBucket),
		},
	})
	if err != nil {
		if awsapi.IsAccessDenied(err) {
			return nil, awsapi.Denied(err, "config:PutDeliveryChannel", defaultRecorderName, e.Principal,
				"if baseline-protection is attached to this account's organizational unit, its "+
					"BP.CFG-2 control denies config:PutDeliveryChannel to every principal in the "+
					"account except automat's own automation role — this session is "+
					"OrganizationAccountAccessRole, not that role, so it is denied even on a first "+
					"deploy if baseline-protection is already attached (the same Q13 ordering "+
					"docs/open-questions.md records for the automation role's own re-permissioning) "+
					"— detach baseline-protection from the OU, apply this deployment, then re-attach "+
					"baseline-protection; if baseline-protection is NOT attached to this OU, grant "+
					"config:PutDeliveryChannel on "+defaultRecorderName+" to "+principalOr(e.Principal)+
					" instead. AWS does not distinguish the two causes, so both are stated")
		}
		return nil, awsapi.Denied(err, "config:PutDeliveryChannel", defaultRecorderName, e.Principal,
			configGrantSentence("config:PutDeliveryChannel", defaultRecorderName, e.Principal))
	}

	detail := "created, delivering to " + spec.DeliveryBucket
	if verb == org.VerbUpdate {
		detail = "repointed to " + spec.DeliveryBucket
	}
	a := e.record(org.Action{
		Verb: verb, Kind: "Config delivery channel", Name: defaultRecorderName, Detail: detail, Applied: true,
	})
	return a, nil
}

// isNoSuchDeliveryChannel reports whether err is AWS Config's own "you asked
// about a delivery channel that does not exist" signal — DescribeDeliveryChannels'
// documented error for a named channel that is absent, the exact parallel
// isNoSuchConfigurationRecorder draws for the recorder's own read.
func isNoSuchDeliveryChannel(err error) bool {
	return awsapi.APIErrorCode(err) == "NoSuchDeliveryChannelException"
}
