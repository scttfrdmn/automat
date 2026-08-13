// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/baseline"
	"github.com/scttfrdmn/automat/internal/envprofile"
)

// RecorderStatus is CheckDetective's finding for the Config recorder: does it
// exist, is it actively recording, and does its recording scope and role
// match what the environment profile's baseline.config_recorder describes.
//
// Three questions rather than one because internal/baseline.EnsureConfigRecorder
// itself makes two independent writes for the identical reason (its own doc
// comment, "the write that makes the resource exist is not the write that
// makes it active") — a recorder can exist, be correctly configured, and
// still be recording nothing because it was Put but never Started, and that
// is a real drift verify must be able to name distinctly from "wrong
// recording group" or "wrong role".
type RecorderStatus struct {
	// Present reports whether a recorder named baseline.DefaultRecorderName
	// exists at all.
	Present bool
	// Recording reports whether it is actively recording. Meaningless when
	// Present is false.
	Recording bool
	// ConfigMatches reports whether its recording group and role match spec —
	// baseline.SameRecorderConfig, the IDENTICAL comparison
	// EnsureConfigRecorder itself uses. Meaningless when Present is false.
	ConfigMatches bool
	// ARN is the recorder's ARN, empty when Present is false.
	ARN string
}

// Clean reports whether the recorder is exactly what the profile describes:
// present, recording, and configured as expected.
func (s *RecorderStatus) Clean() bool {
	return s != nil && s.Present && s.Recording && s.ConfigMatches
}

// DeliveryChannelStatus is CheckDetective's finding for the Config delivery
// channel: does it exist, and does it point at the bucket the profile names.
type DeliveryChannelStatus struct {
	// Present reports whether a delivery channel named
	// baseline.DefaultRecorderName exists at all.
	Present bool
	// Matches reports whether its S3 bucket matches the profile's
	// baseline.config_recorder.delivery_bucket. Meaningless when Present is
	// false.
	Matches bool
	// Bucket is the bucket the profile expects, for a report line — printed
	// regardless of Present/Matches so an operator sees what was expected
	// even when nothing was found.
	Bucket string
}

// Clean reports whether the delivery channel is exactly what the profile
// describes.
func (s *DeliveryChannelStatus) Clean() bool {
	return s != nil && s.Present && s.Matches
}

// ConformancePackStatus is CheckDetective's finding for the conformance
// pack: does a pack of the expected name exist, and do its deployed
// ConformancePackInputParameters match what a fresh compile resolves.
type ConformancePackStatus struct {
	// Name is the conformance pack's expected name.
	Name string
	// Present reports whether a pack of that name exists at all.
	Present bool
	// Matches reports whether its deployed ConformancePackInputParameters
	// match what this compile resolves — baseline.SameInputParameters, the
	// ONLY drift check possible for a conformance pack (that function's own
	// doc comment explains why: DescribeConformancePacks never returns the
	// deployed template text). Meaningless when Present is false.
	Matches bool
	// ARN is the pack's ARN, empty when Present is false.
	ARN string
}

// Clean reports whether the conformance pack is exactly what this compile
// expects.
func (s *ConformancePackStatus) Clean() bool {
	return s != nil && s.Present && s.Matches
}

// DetectiveReport is CheckDetective's result: DESIGN §12's detective layer,
// "recorder on, delivery channel intact, conformance pack present and its
// rule set matches" — the three findings above, each possibly nil.
//
// A nil field is not a failed check; it is "not configured at all", the
// identical "opt-in, and not opted into" distinction checkMirrorDrift's own
// doc comment (cmd/automat/verify.go) draws for the evidence-mirror layer:
// "nothing to check" and "checked, found nothing" are different claims. A
// profile whose baseline.config_recorder.enabled is false never asked for a
// recorder or a delivery channel, and a compile that resolves zero Config
// rules never asked for a conformance pack — reporting either as a failure
// would be checking something the profile never claimed to have installed.
type DetectiveReport struct {
	// Recorder and DeliveryChannel are both nil together: they come from one
	// spec (envprofile.ConfigRecorder) and EnsureConfigRecorder/
	// EnsureDeliveryChannel share its one Enabled field as their common
	// no-op gate (internal/baseline's own doc comment on both methods).
	Recorder        *RecorderStatus
	DeliveryChannel *DeliveryChannelStatus
	// ConformancePack is nil when the compile resolved no Config rule at
	// all — vendConformancePackStep's own no-op branch, mirrored here so
	// verify and vend agree about what "nothing to deploy" means.
	ConformancePack *ConformancePackStatus
}

// Clean reports whether every CONFIGURED finding matches what the profile
// describes. A nil field never makes this false — see the type's own doc
// comment.
func (r *DetectiveReport) Clean() bool {
	if r == nil {
		return true
	}
	if r.Recorder != nil && !r.Recorder.Clean() {
		return false
	}
	if r.DeliveryChannel != nil && !r.DeliveryChannel.Clean() {
		return false
	}
	if r.ConformancePack != nil && !r.ConformancePack.Clean() {
		return false
	}
	return true
}

// CheckDetective compares AWS Config's deployed recorder, delivery channel,
// and conformance pack against what an environment profile describes,
// through awsapi.ConfigVerifyAPI — a client that carries no write method, so
// nothing this function does can change any of the three no matter what it
// finds (ConfigVerifyAPI's own doc comment, the exact guarantee OrgVerifyAPI
// already states for CheckPolicy).
//
// recorderSpec and automationRoleARN are the expected recorder configuration
// — the same envprofile.ConfigRecorder and role ARN vendConfigRecorderStep
// (cmd/automat/vend.go) passes to EnsureConfigRecorder, so "matches" here
// means exactly what it means there. packName and packInputParams are the
// expected conformance pack — packName empty means the compile resolved no
// Config rule at all (vendConformancePackStep's own no-op condition), so the
// caller must pass "" rather than a name computed from a profile that has
// nothing to deploy.
//
// Already-resolved inputs, no opinion about where they came from
// (internal/verify/doc.go's stated architecture): this takes a spec and an
// expected pack, not a profile or an artifact — cmd/automat/verify.go
// resolves both the same way loadVendInput already does for `vend`.
func CheckDetective(ctx context.Context, api awsapi.ConfigVerifyAPI, recorderSpec envprofile.ConfigRecorder,
	automationRoleARN, packName string, packInputParams []configtypes.ConformancePackInputParameter,
) (*DetectiveReport, error) {
	report := &DetectiveReport{}

	if recorderSpec.Enabled {
		rec, err := checkRecorder(ctx, api, recorderSpec, automationRoleARN)
		if err != nil {
			return nil, err
		}
		report.Recorder = rec

		ch, err := checkDeliveryChannel(ctx, api, recorderSpec)
		if err != nil {
			return nil, err
		}
		report.DeliveryChannel = ch
	}

	if packName != "" {
		pack, err := checkConformancePack(ctx, api, packName, packInputParams)
		if err != nil {
			return nil, err
		}
		report.ConformancePack = pack
	}

	return report, nil
}

// checkRecorder reads the recorder's configuration and its recording status,
// mirroring internal/baseline.EnsureConfigRecorder's own two-read shape
// (ensureRecorderConfig, ensureRecorderStarted) exactly, but never writing
// either.
func checkRecorder(ctx context.Context, api awsapi.ConfigVerifyAPI, spec envprofile.ConfigRecorder,
	automationRoleARN string) (*RecorderStatus, error) {
	out, err := api.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{
		ConfigurationRecorderNames: []string{baseline.DefaultRecorderName},
	})
	switch {
	case err == nil:
	case isNoSuchConfigurationRecorder(err):
		return &RecorderStatus{}, nil
	default:
		return nil, denied(err, "config:DescribeConfigurationRecorders", baseline.DefaultRecorderName)
	}

	var rec *configtypes.ConfigurationRecorder
	for i := range out.ConfigurationRecorders {
		if aws.ToString(out.ConfigurationRecorders[i].Name) == baseline.DefaultRecorderName {
			rec = &out.ConfigurationRecorders[i]
			break
		}
	}
	if rec == nil {
		return &RecorderStatus{}, nil
	}

	status := &RecorderStatus{
		Present:       true,
		ARN:           aws.ToString(rec.Arn),
		ConfigMatches: baseline.SameRecorderConfig(rec, spec, automationRoleARN),
	}

	statusOut, err := api.DescribeConfigurationRecorderStatus(ctx,
		&configservice.DescribeConfigurationRecorderStatusInput{
			ConfigurationRecorderNames: []string{baseline.DefaultRecorderName},
		})
	if err != nil {
		return nil, denied(err, "config:DescribeConfigurationRecorderStatus", baseline.DefaultRecorderName)
	}
	for i := range statusOut.ConfigurationRecordersStatus {
		if aws.ToString(statusOut.ConfigurationRecordersStatus[i].Name) == baseline.DefaultRecorderName {
			status.Recording = statusOut.ConfigurationRecordersStatus[i].Recording
			break
		}
	}
	return status, nil
}

// checkDeliveryChannel reads the delivery channel and compares its bucket
// against spec.DeliveryBucket, mirroring
// internal/baseline.EnsureDeliveryChannel's own read half exactly, but never
// writing.
func checkDeliveryChannel(ctx context.Context, api awsapi.ConfigVerifyAPI,
	spec envprofile.ConfigRecorder) (*DeliveryChannelStatus, error) {
	out, err := api.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{
		DeliveryChannelNames: []string{baseline.DefaultRecorderName},
	})
	switch {
	case err == nil:
	case isNoSuchDeliveryChannel(err):
		return &DeliveryChannelStatus{Bucket: spec.DeliveryBucket}, nil
	default:
		return nil, denied(err, "config:DescribeDeliveryChannels", baseline.DefaultRecorderName)
	}

	var ch *configtypes.DeliveryChannel
	for i := range out.DeliveryChannels {
		if aws.ToString(out.DeliveryChannels[i].Name) == baseline.DefaultRecorderName {
			ch = &out.DeliveryChannels[i]
			break
		}
	}
	if ch == nil {
		return &DeliveryChannelStatus{Bucket: spec.DeliveryBucket}, nil
	}
	return &DeliveryChannelStatus{
		Present: true,
		Matches: aws.ToString(ch.S3BucketName) == spec.DeliveryBucket,
		Bucket:  spec.DeliveryBucket,
	}, nil
}

// checkConformancePack reads the conformance pack and compares its deployed
// ConformancePackInputParameters against inputParams, mirroring
// internal/baseline.EnsureConformancePack's own read half exactly, but never
// deploying or redeploying.
func checkConformancePack(ctx context.Context, api awsapi.ConfigVerifyAPI, packName string,
	inputParams []configtypes.ConformancePackInputParameter) (*ConformancePackStatus, error) {
	out, err := api.DescribeConformancePacks(ctx, &configservice.DescribeConformancePacksInput{
		ConformancePackNames: []string{packName},
	})
	switch {
	case err == nil:
	case isNoSuchConformancePack(err):
		return &ConformancePackStatus{Name: packName}, nil
	default:
		return nil, denied(err, "config:DescribeConformancePacks", packName)
	}

	var detail *configtypes.ConformancePackDetail
	for i := range out.ConformancePackDetails {
		if aws.ToString(out.ConformancePackDetails[i].ConformancePackName) == packName {
			detail = &out.ConformancePackDetails[i]
			break
		}
	}
	if detail == nil {
		return &ConformancePackStatus{Name: packName}, nil
	}
	return &ConformancePackStatus{
		Name:    packName,
		Present: true,
		ARN:     aws.ToString(detail.ConformancePackArn),
		Matches: baseline.SameInputParameters(detail.ConformancePackInputParameters, inputParams),
	}, nil
}

// isNoSuchConfigurationRecorder, isNoSuchDeliveryChannel, and
// isNoSuchConformancePack are this package's own copies of
// internal/baseline's identically named, unexported functions — the AWS
// Config "you asked about a resource that does not exist" signal for each of
// the three resources this layer reads. Not shared through an export because
// each is a one-line string comparison against awsapi.APIErrorCode, and
// internal/baseline's own versions are unexported by design (nothing outside
// that package should depend on baseline's internal control flow, only on
// its exported comparators — SameRecorderConfig, SameInputParameters — which
// this file does use).
func isNoSuchConfigurationRecorder(err error) bool {
	return awsapi.APIErrorCode(err) == "NoSuchConfigurationRecorderException"
}

func isNoSuchDeliveryChannel(err error) bool {
	return awsapi.APIErrorCode(err) == "NoSuchDeliveryChannelException"
}

func isNoSuchConformancePack(err error) bool {
	return awsapi.APIErrorCode(err) == "NoSuchConformancePackException"
}
