// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Config fakes awsapi.ConfigAPI: the in-child detective baseline
// (internal/baseline, not yet built) will read and write through this to
// ensure a recorder, a delivery channel, and a conformance pack exist and are
// running, the way internal/org's Ensure* functions already do for
// Organizations resources.
//
// Keyed by name, even though the real API caps an account at one recorder and
// one channel each (MaxNumberOfConfigurationRecordersExceededException /
// MaxNumberOfDeliveryChannelsExceededException): a map keyed the same way
// ConformancePacks already has to be — an account CAN hold more than one
// conformance pack — keeps all three collections the same shape, so a test
// asserting "no second Put occurred" reads the same way for all three rather
// than treating the singleton pair as special cases.
type Config struct {
	Recorder

	// Recorders holds the configuration recorder(s) that have been Put, by
	// name.
	Recorders map[string]configtypes.ConfigurationRecorder
	// RecorderRunning is separate from Recorders holding an entry, on
	// purpose: this is the fake's half of the "created but not enabled" trap
	// ConfigAPI's own doc comment describes for StartConfigurationRecorder —
	// PutConfigurationRecorder alone must not mark a recorder running, or a
	// test could not tell an ensure operation that forgot to Start from one
	// that did.
	RecorderRunning map[string]bool

	// DeliveryChannels holds the delivery channel(s) that have been Put, by
	// name.
	DeliveryChannels map[string]configtypes.DeliveryChannel

	// ConformancePacks holds every deployed pack by name.
	// ConformancePackStatuses holds each one's async deployment state,
	// separate from the map above for the same reason createRequest is
	// separate from fakeAccount in orgvend.go: PutConformancePack returning
	// success and the pack actually being live are two different moments,
	// and DescribeConformancePackStatus is the poll target that tells them
	// apart.
	ConformancePacks        map[string]configtypes.ConformancePackDetail
	ConformancePackStatuses map[string]configtypes.ConformancePackState

	// StatusPollsLeft is how many DescribeConformancePackStatus calls report
	// CREATE_IN_PROGRESS, per pack name, before flipping to CREATE_COMPLETE. A
	// pack absent from this map completes on the first poll — the fake's
	// default is "fast", and a test that wants to exercise a poll loop sets an
	// entry here before calling PutConformancePack.
	StatusPollsLeft map[string]int

	// Per-method error injection, following the naming convention the other
	// fakes in this package use (e.g. KMS.SignErr): each field, when set, is
	// returned in place of the named call's ordinary result. AccessDenied and
	// Throttled (recorder.go) construct the two shapes automat's remediation
	// text and retry logic branch on.
	DescribeConfigurationRecordersErr      error
	DescribeDeliveryChannelsErr            error
	DescribeConformancePacksErr            error
	PutConfigurationRecorderErr            error
	PutDeliveryChannelErr                  error
	PutConformancePackErr                  error
	DescribeConformancePackStatusErr       error
	StartConfigurationRecorderErr          error
	DescribeConfigurationRecorderStatusErr error
}

// NewConfig returns a Config fake with no recorder, channel, or conformance
// pack yet — the state a freshly created member account is in before
// baselining runs.
func NewConfig() *Config {
	return &Config{
		Recorders:               map[string]configtypes.ConfigurationRecorder{},
		RecorderRunning:         map[string]bool{},
		DeliveryChannels:        map[string]configtypes.DeliveryChannel{},
		ConformancePacks:        map[string]configtypes.ConformancePackDetail{},
		ConformancePackStatuses: map[string]configtypes.ConformancePackState{},
		StatusPollsLeft:         map[string]int{},
	}
}

// DescribeConfigurationRecorders implements awsapi.ConfigAPI.
//
// Filters by ConfigurationRecorderNames when the caller names one, and
// returns every recorder otherwise — the real API's own documented shape
// (DescribeConfigurationRecordersInput's own doc comment: "you can only
// specify one configuration recorder" when naming any at all).
func (f *Config) DescribeConfigurationRecorders(_ context.Context, in *configservice.DescribeConfigurationRecordersInput,
	_ ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	f.Record("DescribeConfigurationRecorders")
	if f.DescribeConfigurationRecordersErr != nil {
		return nil, f.DescribeConfigurationRecordersErr
	}
	names := in.ConfigurationRecorderNames
	var out []configtypes.ConfigurationRecorder
	for name, rec := range f.Recorders {
		if len(names) > 0 && !containsString(names, name) {
			continue
		}
		out = append(out, rec)
	}
	return &configservice.DescribeConfigurationRecordersOutput{ConfigurationRecorders: out}, nil
}

// DescribeDeliveryChannels implements awsapi.ConfigAPI.
func (f *Config) DescribeDeliveryChannels(_ context.Context, in *configservice.DescribeDeliveryChannelsInput,
	_ ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error) {
	f.Record("DescribeDeliveryChannels")
	if f.DescribeDeliveryChannelsErr != nil {
		return nil, f.DescribeDeliveryChannelsErr
	}
	names := in.DeliveryChannelNames
	var out []configtypes.DeliveryChannel
	for name, ch := range f.DeliveryChannels {
		if len(names) > 0 && !containsString(names, name) {
			continue
		}
		out = append(out, ch)
	}
	return &configservice.DescribeDeliveryChannelsOutput{DeliveryChannels: out}, nil
}

// DescribeConformancePacks implements awsapi.ConfigAPI.
//
// Unfiltered when the caller names no packs, matching the real API's own
// documented behavior for an empty ConformancePackNames — an ensure operation
// that wants to check for one pack by name still has to filter client-side or
// pass the name, the same shape ListPolicies makes automat filter for its own
// policies among central IT's.
func (f *Config) DescribeConformancePacks(_ context.Context, in *configservice.DescribeConformancePacksInput,
	_ ...func(*configservice.Options)) (*configservice.DescribeConformancePacksOutput, error) {
	f.Record("DescribeConformancePacks")
	if f.DescribeConformancePacksErr != nil {
		return nil, f.DescribeConformancePacksErr
	}
	names := in.ConformancePackNames
	var out []configtypes.ConformancePackDetail
	for name, pack := range f.ConformancePacks {
		if len(names) > 0 && !containsString(names, name) {
			continue
		}
		out = append(out, pack)
	}
	return &configservice.DescribeConformancePacksOutput{ConformancePackDetails: out}, nil
}

// PutConfigurationRecorder implements awsapi.ConfigAPI.
//
// Create-or-replace, matching the real call: Config's own
// PutConfigurationRecorder has no separate update method, the same shape
// IAMRole.PutRolePolicy already reproduces for IAM's inline policies.
// Deliberately does NOT mark the recorder running — see RecorderRunning's own
// comment.
func (f *Config) PutConfigurationRecorder(_ context.Context, in *configservice.PutConfigurationRecorderInput,
	_ ...func(*configservice.Options)) (*configservice.PutConfigurationRecorderOutput, error) {
	f.Record("PutConfigurationRecorder")
	if f.PutConfigurationRecorderErr != nil {
		return nil, f.PutConfigurationRecorderErr
	}
	name := aws.ToString(in.ConfigurationRecorder.Name)
	if name == "" {
		name = "default"
	}
	rec := *in.ConfigurationRecorder
	rec.Name = aws.String(name)
	f.Recorders[name] = rec
	return &configservice.PutConfigurationRecorderOutput{}, nil
}

// PutDeliveryChannel implements awsapi.ConfigAPI.
func (f *Config) PutDeliveryChannel(_ context.Context, in *configservice.PutDeliveryChannelInput,
	_ ...func(*configservice.Options)) (*configservice.PutDeliveryChannelOutput, error) {
	f.Record("PutDeliveryChannel")
	if f.PutDeliveryChannelErr != nil {
		return nil, f.PutDeliveryChannelErr
	}
	name := aws.ToString(in.DeliveryChannel.Name)
	if name == "" {
		name = "default"
	}
	ch := *in.DeliveryChannel
	ch.Name = aws.String(name)
	f.DeliveryChannels[name] = ch
	return &configservice.PutDeliveryChannelOutput{}, nil
}

// PutConformancePack implements awsapi.ConfigAPI.
//
// Returns immediately, like the real call — the pack is CREATE_IN_PROGRESS
// (or already exists, if the caller Put the same name twice) and
// DescribeConformancePackStatus is where the async completion is observed,
// the same "accepted, not finished" split OrgVend.CreateAccount uses for
// DescribeCreateAccountStatus.
func (f *Config) PutConformancePack(_ context.Context, in *configservice.PutConformancePackInput,
	_ ...func(*configservice.Options)) (*configservice.PutConformancePackOutput, error) {
	f.Record("PutConformancePack")
	if f.PutConformancePackErr != nil {
		return nil, f.PutConformancePackErr
	}
	name := aws.ToString(in.ConformancePackName)
	arn := "arn:aws:config:us-east-1:111111111111:conformance-pack/" + name + "/cp-fake"
	f.ConformancePacks[name] = configtypes.ConformancePackDetail{
		ConformancePackArn:  aws.String(arn),
		ConformancePackId:   aws.String("cp-fake"),
		ConformancePackName: aws.String(name),
		// Persisted, matching real AWS Config: DescribeConformancePacks'
		// own ConformancePackDetail.ConformancePackInputParameters echoes
		// back exactly what PutConformancePack was last called with
		// (API_ConformancePackDetail's own field list) — the ONE field
		// AWS's read side ever returns for a deployed pack, since neither
		// this API nor any other hands the deployed TemplateBody back to a
		// caller. Without this, a caller cannot detect drift at all, which
		// is exactly the fidelity internal/baseline.EnsureConformancePack
		// (its first production consumer) depends on for its own
		// read-then-branch.
		ConformancePackInputParameters: in.ConformancePackInputParameters,
	}
	f.ConformancePackStatuses[name] = configtypes.ConformancePackStateCreateInProgress
	return &configservice.PutConformancePackOutput{ConformancePackArn: aws.String(arn)}, nil
}

// DescribeConformancePackStatus implements awsapi.ConfigAPI.
//
// The poll target for PutConformancePack's async deployment. StatusPollsLeft
// lets a test choose how many IN_PROGRESS answers precede CREATE_COMPLETE,
// the same knob OrgState.CreateAccountPolls gives CreateAccount — a fake that
// completed instantly would let a missing poll loop pass unnoticed.
func (f *Config) DescribeConformancePackStatus(_ context.Context, in *configservice.DescribeConformancePackStatusInput,
	_ ...func(*configservice.Options)) (*configservice.DescribeConformancePackStatusOutput, error) {
	f.Record("DescribeConformancePackStatus")
	if f.DescribeConformancePackStatusErr != nil {
		return nil, f.DescribeConformancePackStatusErr
	}
	names := in.ConformancePackNames
	var out []configtypes.ConformancePackStatusDetail
	for name, pack := range f.ConformancePacks {
		if len(names) > 0 && !containsString(names, name) {
			continue
		}
		state := f.ConformancePackStatuses[name]
		if state == configtypes.ConformancePackStateCreateInProgress {
			if left := f.StatusPollsLeft[name]; left > 0 {
				f.StatusPollsLeft[name] = left - 1
			} else {
				state = configtypes.ConformancePackStateCreateComplete
				f.ConformancePackStatuses[name] = state
			}
		}
		out = append(out, configtypes.ConformancePackStatusDetail{
			ConformancePackArn:   pack.ConformancePackArn,
			ConformancePackId:    pack.ConformancePackId,
			ConformancePackName:  pack.ConformancePackName,
			ConformancePackState: state,
			StackArn:             aws.String("arn:aws:cloudformation:us-east-1:111111111111:stack/cp-fake/fake"),
		})
	}
	return &configservice.DescribeConformancePackStatusOutput{ConformancePackStatusDetails: out}, nil
}

// StartConfigurationRecorder implements awsapi.ConfigAPI.
//
// NoSuchConfigurationRecorderException when the named recorder does not
// exist, matching the real API: Start against a recorder that was never Put
// is a caller error, not a no-op — the same distinction OrgVend.MoveAccount
// draws between "already there" and "never existed".
func (f *Config) StartConfigurationRecorder(_ context.Context, in *configservice.StartConfigurationRecorderInput,
	_ ...func(*configservice.Options)) (*configservice.StartConfigurationRecorderOutput, error) {
	f.Record("StartConfigurationRecorder")
	if f.StartConfigurationRecorderErr != nil {
		return nil, f.StartConfigurationRecorderErr
	}
	name := aws.ToString(in.ConfigurationRecorderName)
	if _, ok := f.Recorders[name]; !ok {
		return nil, &APIError{
			Code:    "NoSuchConfigurationRecorderException",
			Message: "Cannot start the Configuration Recorder because it does not exist.",
		}
	}
	f.RecorderRunning[name] = true
	return &configservice.StartConfigurationRecorderOutput{}, nil
}

// DescribeConfigurationRecorderStatus implements awsapi.ConfigAPI.
//
// Recording reflects RecorderRunning directly — the fake's own half of the
// "created but not enabled" trap (RecorderRunning's own doc comment): a
// recorder present in Recorders but absent from RecorderRunning reports
// Recording: false, exactly the state a Put-without-Start leaves a real
// recorder in. A name absent from Recorders entirely is filtered out of the
// response rather than erroring — DescribeConfigurationRecorderStatus's own
// documented behavior for an unspecified name is "status for the customer
// managed configuration recorder configured for the account", and this fake
// has at most one, so naming it explicitly or not produces the same result.
func (f *Config) DescribeConfigurationRecorderStatus(_ context.Context, in *configservice.DescribeConfigurationRecorderStatusInput,
	_ ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	f.Record("DescribeConfigurationRecorderStatus")
	if f.DescribeConfigurationRecorderStatusErr != nil {
		return nil, f.DescribeConfigurationRecorderStatusErr
	}
	names := in.ConfigurationRecorderNames
	var out []configtypes.ConfigurationRecorderStatus
	for name, rec := range f.Recorders {
		if len(names) > 0 && !containsString(names, name) {
			continue
		}
		out = append(out, configtypes.ConfigurationRecorderStatus{
			Name:      aws.String(name),
			Arn:       rec.Arn,
			Recording: f.RecorderRunning[name],
		})
	}
	return &configservice.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: out}, nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

var _ awsapi.ConfigAPI = (*Config)(nil)
