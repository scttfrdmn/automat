// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/baseline"
	"github.com/scttfrdmn/automat/internal/envprofile"
)

const testDetectiveRoleARN = "arn:aws:iam::222222222222:role/automat-automation"

func recorderSpec() envprofile.ConfigRecorder {
	return envprofile.ConfigRecorder{Enabled: true, DeliveryBucket: "campus-config-evidence"}
}

func testPackParams() []configtypes.ConformancePackInputParameter {
	return []configtypes.ConformancePackInputParameter{
		{ParameterName: aws.String("RuleParam"), ParameterValue: aws.String("v1")},
	}
}

// deployedRecorder puts a recorder into cfg exactly matching spec/roleARN,
// through the fake's own PutConfigurationRecorder — reusing the exact fixture
// EnsureConfigRecorder's own tests use, so "matches" here means what it
// means there.
func deployMatchingRecorder(t *testing.T, cfg *awsfake.Config, spec envprofile.ConfigRecorder, roleARN string) {
	t.Helper()
	if _, err := cfg.PutConfigurationRecorder(context.Background(), &configservice.PutConfigurationRecorderInput{
		ConfigurationRecorder: &configtypes.ConfigurationRecorder{
			Name:    aws.String(baseline.DefaultRecorderName),
			RoleARN: aws.String(roleARN),
			Arn:     aws.String("arn:aws:config:us-east-1:222222222222:config-recorder/default"),
			RecordingGroup: &configtypes.RecordingGroup{
				AllSupported:               spec.RecordsAllSupportedResources(),
				IncludeGlobalResourceTypes: spec.RecordsGlobalResourceTypes(),
			},
		},
	}); err != nil {
		t.Fatalf("seed recorder: %v", err)
	}
	if _, err := cfg.StartConfigurationRecorder(context.Background(),
		&configservice.StartConfigurationRecorderInput{
			ConfigurationRecorderName: aws.String(baseline.DefaultRecorderName),
		}); err != nil {
		t.Fatalf("seed recorder start: %v", err)
	}
}

func deployMatchingChannel(t *testing.T, cfg *awsfake.Config, bucket string) {
	t.Helper()
	if _, err := cfg.PutDeliveryChannel(context.Background(), &configservice.PutDeliveryChannelInput{
		DeliveryChannel: &configtypes.DeliveryChannel{
			Name:         aws.String(baseline.DefaultRecorderName),
			S3BucketName: aws.String(bucket),
		},
	}); err != nil {
		t.Fatalf("seed delivery channel: %v", err)
	}
}

func deployMatchingPack(t *testing.T, cfg *awsfake.Config, name string,
	params []configtypes.ConformancePackInputParameter) {
	t.Helper()
	if _, err := cfg.PutConformancePack(context.Background(), &configservice.PutConformancePackInput{
		ConformancePackName:            aws.String(name),
		TemplateBody:                   aws.String("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"),
		ConformancePackInputParameters: params,
	}); err != nil {
		t.Fatalf("seed conformance pack: %v", err)
	}
}

// TestCheckDetectiveAllClean is the property CheckDetective exists to hold:
// a recorder, a delivery channel, and a conformance pack all deployed
// exactly as a fresh compile would produce them must report clean across
// the board.
func TestCheckDetectiveAllClean(t *testing.T) {
	cfg := awsfake.NewConfig()
	spec := recorderSpec()
	deployMatchingRecorder(t, cfg, spec, testDetectiveRoleARN)
	deployMatchingChannel(t, cfg, spec.DeliveryBucket)
	deployMatchingPack(t, cfg, "automat-research-cui", testPackParams())

	report, err := CheckDetective(context.Background(), cfg, spec, testDetectiveRoleARN,
		"automat-research-cui", testPackParams())
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: %+v", report)
	}
	if report.Recorder == nil || !report.Recorder.Present || !report.Recorder.Recording || !report.Recorder.ConfigMatches {
		t.Errorf("Recorder = %+v, want present/recording/matching", report.Recorder)
	}
	if report.DeliveryChannel == nil || !report.DeliveryChannel.Present || !report.DeliveryChannel.Matches {
		t.Errorf("DeliveryChannel = %+v, want present/matching", report.DeliveryChannel)
	}
	if report.ConformancePack == nil || !report.ConformancePack.Present || !report.ConformancePack.Matches {
		t.Errorf("ConformancePack = %+v, want present/matching", report.ConformancePack)
	}
}

// TestCheckDetectiveRecorderConfigDrifted holds the independent
// ConfigMatches finding: a recorder deployed with a DIFFERENT recording
// scope than the profile now describes must report ConfigMatches: false,
// distinct from Present or Recording.
func TestCheckDetectiveRecorderConfigDrifted(t *testing.T) {
	cfg := awsfake.NewConfig()
	spec := recorderSpec()
	narrower := false
	deployMatchingRecorder(t, cfg, envprofile.ConfigRecorder{Enabled: true, AllSupportedResources: &narrower},
		testDetectiveRoleARN)
	deployMatchingChannel(t, cfg, spec.DeliveryBucket)

	report, err := CheckDetective(context.Background(), cfg, spec, testDetectiveRoleARN, "", nil)
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: the recorder's recording scope has drifted")
	}
	if !report.Recorder.Present || !report.Recorder.Recording {
		t.Errorf("Recorder = %+v, want present and recording despite the config drift", report.Recorder)
	}
	if report.Recorder.ConfigMatches {
		t.Error("ConfigMatches = true, want false: AllSupportedResources differs from spec")
	}
}

// TestCheckDetectiveRecorderNeverStarted is EnsureConfigRecorder's own
// "created but not enabled" trap, read back: a recorder Put but never
// Started must report Present: true, Recording: false — a distinct finding
// from either "absent" or "config drifted".
func TestCheckDetectiveRecorderNeverStarted(t *testing.T) {
	cfg := awsfake.NewConfig()
	spec := recorderSpec()
	if _, err := cfg.PutConfigurationRecorder(context.Background(), &configservice.PutConfigurationRecorderInput{
		ConfigurationRecorder: &configtypes.ConfigurationRecorder{
			Name:    aws.String(baseline.DefaultRecorderName),
			RoleARN: aws.String(testDetectiveRoleARN),
			RecordingGroup: &configtypes.RecordingGroup{
				AllSupported:               spec.RecordsAllSupportedResources(),
				IncludeGlobalResourceTypes: spec.RecordsGlobalResourceTypes(),
			},
		},
	}); err != nil {
		t.Fatalf("seed recorder: %v", err)
	}
	deployMatchingChannel(t, cfg, spec.DeliveryBucket)

	report, err := CheckDetective(context.Background(), cfg, spec, testDetectiveRoleARN, "", nil)
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: the recorder was never started")
	}
	if !report.Recorder.Present {
		t.Error("Present = false, want true")
	}
	if !report.Recorder.ConfigMatches {
		t.Error("ConfigMatches = false, want true: the configuration itself matches")
	}
	if report.Recorder.Recording {
		t.Error("Recording = true, want false: StartConfigurationRecorder was never called")
	}
}

// TestCheckDetectiveDeliveryChannelWrongBucket holds the delivery channel's
// own drift finding, independent of the recorder.
func TestCheckDetectiveDeliveryChannelWrongBucket(t *testing.T) {
	cfg := awsfake.NewConfig()
	spec := recorderSpec()
	deployMatchingRecorder(t, cfg, spec, testDetectiveRoleARN)
	deployMatchingChannel(t, cfg, "some-other-bucket")

	report, err := CheckDetective(context.Background(), cfg, spec, testDetectiveRoleARN, "", nil)
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: the delivery channel points at the wrong bucket")
	}
	if !report.DeliveryChannel.Present {
		t.Error("DeliveryChannel.Present = false, want true")
	}
	if report.DeliveryChannel.Matches {
		t.Error("DeliveryChannel.Matches = true, want false")
	}
	if report.DeliveryChannel.Bucket != spec.DeliveryBucket {
		t.Errorf("DeliveryChannel.Bucket = %q, want the expected bucket %q",
			report.DeliveryChannel.Bucket, spec.DeliveryBucket)
	}
}

// TestCheckDetectiveConformancePackParametersDrifted holds
// baseline.SameInputParameters' own comparison read back: a pack deployed
// with different resolved parameter values must report Matches: false.
func TestCheckDetectiveConformancePackParametersDrifted(t *testing.T) {
	cfg := awsfake.NewConfig()
	deployed := []configtypes.ConformancePackInputParameter{
		{ParameterName: aws.String("RuleParam"), ParameterValue: aws.String("old-value")},
	}
	deployMatchingPack(t, cfg, "automat-research-cui", deployed)

	report, err := CheckDetective(context.Background(), cfg, envprofile.ConfigRecorder{}, "",
		"automat-research-cui", testPackParams())
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: the deployed parameters differ from a fresh compile")
	}
	if !report.ConformancePack.Present {
		t.Error("ConformancePack.Present = false, want true")
	}
	if report.ConformancePack.Matches {
		t.Error("ConformancePack.Matches = true, want false")
	}
}

// TestCheckDetectiveRecorderDisabledIsNotConfigured is the "opt-in, and not
// opted into" case: a profile whose config_recorder.enabled is false must
// report Recorder and DeliveryChannel as nil — NOT as a failure — matching
// checkMirrorDrift's own "nothing to check" vs. "checked, found nothing"
// distinction.
func TestCheckDetectiveRecorderDisabledIsNotConfigured(t *testing.T) {
	cfg := awsfake.NewConfig()

	report, err := CheckDetective(context.Background(), cfg, envprofile.ConfigRecorder{Enabled: false}, "", "", nil)
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: nothing was asked for, so nothing is dirty: %+v", report)
	}
	if report.Recorder != nil {
		t.Errorf("Recorder = %+v, want nil: the profile never asked for one", report.Recorder)
	}
	if report.DeliveryChannel != nil {
		t.Errorf("DeliveryChannel = %+v, want nil: the profile never asked for one", report.DeliveryChannel)
	}
	if n := cfg.CallCount("DescribeConfigurationRecorders"); n != 0 {
		t.Errorf("DescribeConfigurationRecorders called %d times for a disabled recorder, want 0", n)
	}
}

// TestCheckDetectiveNoConformancePackNameIsNotConfigured is
// TestCheckDetectiveRecorderDisabledIsNotConfigured's sibling for the
// conformance pack: an empty packName (a compile that resolved zero Config
// rules, vendConformancePackStep's own no-op condition) must report
// ConformancePack as nil, not as an absent pack that fails the check.
func TestCheckDetectiveNoConformancePackNameIsNotConfigured(t *testing.T) {
	cfg := awsfake.NewConfig()

	report, err := CheckDetective(context.Background(), cfg, envprofile.ConfigRecorder{}, "", "", nil)
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if report.ConformancePack != nil {
		t.Errorf("ConformancePack = %+v, want nil: no pack was named", report.ConformancePack)
	}
	if n := cfg.CallCount("DescribeConformancePacks"); n != 0 {
		t.Errorf("DescribeConformancePacks called %d times with no pack name, want 0", n)
	}
}

// TestCheckDetectiveNothingDeployedYet is the case a fresh account not yet
// baselined must report: recorder, channel, and pack all named but nothing
// exists, which is Present: false everywhere, a real (not "unknown")
// finding.
func TestCheckDetectiveNothingDeployedYet(t *testing.T) {
	cfg := awsfake.NewConfig()
	spec := recorderSpec()

	report, err := CheckDetective(context.Background(), cfg, spec, testDetectiveRoleARN,
		"automat-research-cui", testPackParams())
	if err != nil {
		t.Fatalf("CheckDetective: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: nothing has been deployed")
	}
	if report.Recorder == nil || report.Recorder.Present {
		t.Errorf("Recorder = %+v, want present: false", report.Recorder)
	}
	if report.DeliveryChannel == nil || report.DeliveryChannel.Present {
		t.Errorf("DeliveryChannel = %+v, want present: false", report.DeliveryChannel)
	}
	if report.ConformancePack == nil || report.ConformancePack.Present {
		t.Errorf("ConformancePack = %+v, want present: false", report.ConformancePack)
	}
}

// TestCheckDetectiveDeniedReadIsAnError holds CheckDetective's read-only
// error path: a denied Describe call must surface as a *awsapi.PermissionError
// naming the action, exactly like CheckPolicy's own TestCheckPolicyDenied —
// not as a silent "not present".
func TestCheckDetectiveDeniedReadIsAnError(t *testing.T) {
	cfg := awsfake.NewConfig()
	cfg.DescribeConfigurationRecordersErr = awsfake.AccessDenied("config:DescribeConfigurationRecorders")

	_, err := CheckDetective(context.Background(), cfg, recorderSpec(), testDetectiveRoleARN, "", nil)
	if err == nil {
		t.Fatal("CheckDetective succeeded despite a denied read, want an error")
	}
	if pe, ok := awsapi.AsPermissionError(err); !ok || pe.Action != "config:DescribeConfigurationRecorders" {
		t.Errorf("error = %v, want a *awsapi.PermissionError naming DescribeConfigurationRecorders", err)
	}
}
