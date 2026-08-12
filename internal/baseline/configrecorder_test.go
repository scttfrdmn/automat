// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/org"
)

const testAutomationRoleARN = "arn:aws:iam::222222222222:role/automat-automation"

// TestEnsureConfigRecorderNoOpWhenDisabled confirms spec.Enabled: false
// produces no action and no AWS call at all — the true no-op discipline
// EnsureRegions' own doc comment describes for a profile naming no
// baseline.regions block.
func TestEnsureConfigRecorderNoOpWhenDisabled(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)

	actions, err := e.EnsureConfigRecorder(ctx(), envprofile.ConfigRecorder{Enabled: false}, testAutomationRoleARN)
	if err != nil {
		t.Fatalf("EnsureConfigRecorder: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("want no actions for a disabled recorder, got %+v", actions)
	}
	for _, op := range []string{"DescribeConfigurationRecorders", "PutConfigurationRecorder",
		"StartConfigurationRecorder", "DescribeConfigurationRecorderStatus"} {
		if n := cfg.CallCount(op); n != 0 {
			t.Errorf("%s called %d times for a disabled recorder, want 0", op, n)
		}
	}
}

// TestEnsureConfigRecorderPlanCreatesNothing is CLAUDE.md rule 5: a plan must
// issue no mutating call, on a first-ensure.
func TestEnsureConfigRecorderPlanCreatesNothing(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModePlan)

	actions, err := e.EnsureConfigRecorder(ctx(), envprofile.ConfigRecorder{Enabled: true}, testAutomationRoleARN)
	if err != nil {
		t.Fatalf("EnsureConfigRecorder: %v", err)
	}
	for _, op := range []string{"PutConfigurationRecorder", "StartConfigurationRecorder"} {
		if n := cfg.CallCount(op); n != 0 {
			t.Errorf("plan mode called %s %d times; a plan must write nothing", op, n)
		}
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbCreate || actions[0].Applied {
		t.Fatalf("want one unapplied create action for the recorder's configuration, got %+v", actions)
	}
}

// TestEnsureConfigRecorderApplyCreatesAndStarts is this slice's headline
// test: a first apply must PutConfigurationRecorder AND
// StartConfigurationRecorder — the "created but not enabled" trap
// EnsureConfigRecorder's own doc comment cites EnsureSCPEnabled's precedent
// for. Two actions, not one.
func TestEnsureConfigRecorderApplyCreatesAndStarts(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)

	actions, err := e.EnsureConfigRecorder(ctx(), envprofile.ConfigRecorder{Enabled: true}, testAutomationRoleARN)
	if err != nil {
		t.Fatalf("EnsureConfigRecorder: %v", err)
	}
	if n := cfg.CallCount("PutConfigurationRecorder"); n != 1 {
		t.Errorf("PutConfigurationRecorder called %d times, want 1", n)
	}
	if n := cfg.CallCount("StartConfigurationRecorder"); n != 1 {
		t.Errorf("StartConfigurationRecorder called %d times, want 1", n)
	}
	if len(actions) != 2 {
		t.Fatalf("want two actions (configure, then start), got %d: %+v", len(actions), actions)
	}
	if actions[0].Verb != org.VerbCreate || !actions[0].Applied {
		t.Errorf("first action = %+v, want an applied create", actions[0])
	}
	if actions[1].Verb != org.VerbEnable || !actions[1].Applied {
		t.Errorf("second action = %+v, want an applied enable (the Start call)", actions[1])
	}
	if !cfg.RecorderRunning["default"] {
		t.Error("the fake's recorder is not marked running after EnsureConfigRecorder's apply")
	}
	rec, ok := cfg.Recorders["default"]
	if !ok {
		t.Fatal("no recorder named \"default\" was created")
	}
	if got := *rec.RoleARN; got != testAutomationRoleARN {
		t.Errorf("recorder RoleARN = %q, want %q", got, testAutomationRoleARN)
	}
	if rec.RecordingGroup == nil || !rec.RecordingGroup.AllSupported {
		t.Errorf("recorder RecordingGroup = %+v, want AllSupported: true (the schema default)", rec.RecordingGroup)
	}
}

// TestEnsureConfigRecorderIdempotent is CLAUDE.md rule 4: a second apply
// against an unchanged desired state — recorder already configured AND
// already recording — must issue no write at all.
func TestEnsureConfigRecorderIdempotent(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	spec := envprofile.ConfigRecorder{Enabled: true}
	if _, err := e.EnsureConfigRecorder(ctx(), spec, testAutomationRoleARN); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	cfg.Reset()

	actions, err := e.EnsureConfigRecorder(ctx(), spec, testAutomationRoleARN)
	if err != nil {
		t.Fatalf("EnsureConfigRecorder: %v", err)
	}
	for _, op := range []string{"PutConfigurationRecorder", "StartConfigurationRecorder"} {
		if n := cfg.CallCount(op); n != 0 {
			t.Errorf("%s called %d times on an unchanged re-run, want 0", op, n)
		}
	}
	for _, a := range actions {
		if a.Verb != org.VerbUnchanged || a.Applied {
			t.Errorf("want every action unchanged and unapplied on a re-run, got %+v", a)
		}
	}
}

// TestEnsureConfigRecorderDriftTriggersUpdate confirms a recorder already
// deployed with a DIFFERENT recording scope than spec now describes (a
// profile edit narrowing or widening all_supported_resources or
// include_global_resource_types) is corrected via a second
// PutConfigurationRecorder.
func TestEnsureConfigRecorderDriftTriggersUpdate(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	narrow := false
	if _, err := e.EnsureConfigRecorder(ctx(),
		envprofile.ConfigRecorder{Enabled: true, AllSupportedResources: &narrow}, testAutomationRoleARN); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	cfg.Reset()

	actions, err := e.EnsureConfigRecorder(ctx(), envprofile.ConfigRecorder{Enabled: true}, testAutomationRoleARN)
	if err != nil {
		t.Fatalf("EnsureConfigRecorder: %v", err)
	}
	if n := cfg.CallCount("PutConfigurationRecorder"); n != 1 {
		t.Errorf("PutConfigurationRecorder called %d times, want 1", n)
	}
	if len(actions) == 0 || actions[0].Verb != org.VerbUpdate || !actions[0].Applied {
		t.Fatalf("want an applied update action for the drifted recording scope, got %+v", actions)
	}
	rec := cfg.Recorders["default"]
	if !rec.RecordingGroup.AllSupported {
		t.Error("the recorder was not corrected to AllSupported: true")
	}
}

// TestEnsureConfigRecorderStartsAnAlreadyConfiguredButNeverStartedRecorder is
// the specific "created but not enabled" scenario: an out-of-band process
// (or an earlier partial run) Put the recorder correctly, but it was never
// started. A re-run must still call StartConfigurationRecorder even though
// the configuration half needs no write at all.
func TestEnsureConfigRecorderStartsAnAlreadyConfiguredButNeverStartedRecorder(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	spec := envprofile.ConfigRecorder{Enabled: true}

	// Seed the recorder's configuration directly, bypassing PutConfigurationRecorder
	// so RecorderRunning is never set — see PutConfigurationRecorder's own doc
	// comment ("Deliberately does NOT mark the recorder running").
	if _, err := e.EnsureConfigRecorder(ctx(), spec, testAutomationRoleARN); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	// Undo the start half only, simulating a recorder that exists but was
	// never (or no longer) started.
	cfg.RecorderRunning["default"] = false
	cfg.Reset()

	actions, err := e.EnsureConfigRecorder(ctx(), spec, testAutomationRoleARN)
	if err != nil {
		t.Fatalf("EnsureConfigRecorder: %v", err)
	}
	if n := cfg.CallCount("PutConfigurationRecorder"); n != 0 {
		t.Errorf("PutConfigurationRecorder called %d times; the configuration half is unchanged, want 0", n)
	}
	if n := cfg.CallCount("StartConfigurationRecorder"); n != 1 {
		t.Errorf("StartConfigurationRecorder called %d times, want 1", n)
	}
	if len(actions) != 2 {
		t.Fatalf("want two actions (unchanged config, then an applied start), got %d: %+v", len(actions), actions)
	}
	if actions[0].Verb != org.VerbUnchanged {
		t.Errorf("first action = %+v, want unchanged (the configuration half)", actions[0])
	}
	if actions[1].Verb != org.VerbEnable || !actions[1].Applied {
		t.Errorf("second action = %+v, want an applied enable (the Start call)", actions[1])
	}
}

// TestEnsureConfigRecorderRefusesWithNoAutomationRoleARN confirms the plan-
// time refusal rather than letting PutConfigurationRecorder fail on a nil
// RoleARN deep in an apply.
func TestEnsureConfigRecorderRefusesWithNoAutomationRoleARN(t *testing.T) {
	e, _ := newConfigFixtureEnsurer(org.ModeApply)
	if _, err := e.EnsureConfigRecorder(ctx(), envprofile.ConfigRecorder{Enabled: true}, ""); err == nil {
		t.Fatal("want an error when no automation role ARN is given")
	}
}

// TestEnsureConfigRecorderParksOnPutDenial is BP.CFG-1's own Q13-shaped
// scenario, the exact parallel TestEnsureConformancePackParksOnPutDenial
// draws for BP.CFG-3: this session is always the assumed
// OrganizationAccountAccessRole, never automat:automation-role, so a denial
// on PutConfigurationRecorder may be Q13 even on what looks like the first
// deploy from this Ensurer's own point of view.
func TestEnsureConfigRecorderParksOnPutDenial(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	cfg.PutConfigurationRecorderErr = awsfake.AccessDenied("config:PutConfigurationRecorder")

	_, err := e.EnsureConfigRecorder(ctx(), envprofile.ConfigRecorder{Enabled: true}, testAutomationRoleARN)
	if err == nil {
		t.Fatal("want an error when PutConfigurationRecorder is denied")
	}
	if !org.Parkable(err) {
		t.Errorf("this denial must be org.Parkable so `vend` parks rather than fails outright: %v", err)
	}
	if !strings.Contains(err.Error(), "baseline-protection") {
		t.Errorf("error does not mention baseline-protection (BP.CFG-1): %v", err)
	}
	if !strings.Contains(err.Error(), "detach baseline-protection") {
		t.Errorf("error carries no remediation to detach baseline-protection: %v", err)
	}
}

// TestEnsureConfigRecorderParksOnStartDenial is the Start half's own version
// of the same scenario: the configuration half succeeds (or is already
// correct) but StartConfigurationRecorder is denied.
func TestEnsureConfigRecorderParksOnStartDenial(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	cfg.StartConfigurationRecorderErr = awsfake.AccessDenied("config:StartConfigurationRecorder")

	_, err := e.EnsureConfigRecorder(ctx(), envprofile.ConfigRecorder{Enabled: true}, testAutomationRoleARN)
	if err == nil {
		t.Fatal("want an error when StartConfigurationRecorder is denied")
	}
	if !org.Parkable(err) {
		t.Errorf("this denial must be org.Parkable so `vend` parks rather than fails outright: %v", err)
	}
	if !strings.Contains(err.Error(), "baseline-protection") {
		t.Errorf("error does not mention baseline-protection (BP.CFG-1): %v", err)
	}
	// The recorder's own configuration write must still be recorded as
	// Applied — only the Start call failed.
	if n := cfg.CallCount("PutConfigurationRecorder"); n != 1 {
		t.Errorf("PutConfigurationRecorder called %d times, want 1", n)
	}
}

// --- EnsureDeliveryChannel ---

const testDeliveryBucket = "campus-config-evidence"

// TestEnsureDeliveryChannelNoOpWhenDisabled mirrors
// TestEnsureConfigRecorderNoOpWhenDisabled for the delivery channel.
func TestEnsureDeliveryChannelNoOpWhenDisabled(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)

	action, err := e.EnsureDeliveryChannel(ctx(), envprofile.ConfigRecorder{Enabled: false})
	if err != nil {
		t.Fatalf("EnsureDeliveryChannel: %v", err)
	}
	if action != nil {
		t.Errorf("want no action for a disabled recorder, got %+v", action)
	}
	if n := cfg.CallCount("DescribeDeliveryChannels"); n != 0 {
		t.Errorf("DescribeDeliveryChannels called %d times for a disabled recorder, want 0", n)
	}
}

// TestEnsureDeliveryChannelRefusesWithNoBucket is the scope-cut's own
// plan-time refusal: baseline.config_recorder.delivery_bucket must name a
// pre-existing, operator-named bucket, and an empty value is refused before
// any AWS call rather than let PutDeliveryChannel fail on a nil S3BucketName.
func TestEnsureDeliveryChannelRefusesWithNoBucket(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)

	_, err := e.EnsureDeliveryChannel(ctx(), envprofile.ConfigRecorder{Enabled: true})
	if err == nil {
		t.Fatal("want an error when the recorder is enabled but delivery_bucket is empty")
	}
	if !strings.Contains(err.Error(), "delivery_bucket") {
		t.Errorf("error does not name the missing field: %v", err)
	}
	if n := cfg.CallCount("DescribeDeliveryChannels"); n != 0 {
		t.Errorf("DescribeDeliveryChannels called %d times; the refusal must happen before any AWS "+
			"call, want 0", n)
	}
	for _, op := range []string{"PutDeliveryChannel"} {
		if n := cfg.CallCount(op); n != 0 {
			t.Errorf("%s called %d times; automat must never create a bucket-less delivery channel, want 0", op, n)
		}
	}
}

// TestEnsureDeliveryChannelPlanCreatesNothing is CLAUDE.md rule 5.
func TestEnsureDeliveryChannelPlanCreatesNothing(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModePlan)

	action, err := e.EnsureDeliveryChannel(ctx(), envprofile.ConfigRecorder{Enabled: true, DeliveryBucket: testDeliveryBucket})
	if err != nil {
		t.Fatalf("EnsureDeliveryChannel: %v", err)
	}
	if n := cfg.CallCount("PutDeliveryChannel"); n != 0 {
		t.Errorf("plan mode called PutDeliveryChannel %d times; a plan must write nothing", n)
	}
	if action == nil || action.Verb != org.VerbCreate || action.Applied {
		t.Fatalf("want one unapplied create action, got %+v", action)
	}
}

// TestEnsureDeliveryChannelApplyCreates is the apply-mode counterpart.
func TestEnsureDeliveryChannelApplyCreates(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)

	action, err := e.EnsureDeliveryChannel(ctx(), envprofile.ConfigRecorder{Enabled: true, DeliveryBucket: testDeliveryBucket})
	if err != nil {
		t.Fatalf("EnsureDeliveryChannel: %v", err)
	}
	if n := cfg.CallCount("PutDeliveryChannel"); n != 1 {
		t.Errorf("PutDeliveryChannel called %d times, want 1", n)
	}
	if action == nil || action.Verb != org.VerbCreate || !action.Applied {
		t.Fatalf("want one applied create action, got %+v", action)
	}
	ch, ok := cfg.DeliveryChannels["default"]
	if !ok {
		t.Fatal("no delivery channel named \"default\" was created")
	}
	if got := *ch.S3BucketName; got != testDeliveryBucket {
		t.Errorf("delivery channel S3BucketName = %q, want %q", got, testDeliveryBucket)
	}
}

// TestEnsureDeliveryChannelIdempotent is CLAUDE.md rule 4.
func TestEnsureDeliveryChannelIdempotent(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	spec := envprofile.ConfigRecorder{Enabled: true, DeliveryBucket: testDeliveryBucket}
	if _, err := e.EnsureDeliveryChannel(ctx(), spec); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	cfg.Reset()

	action, err := e.EnsureDeliveryChannel(ctx(), spec)
	if err != nil {
		t.Fatalf("EnsureDeliveryChannel: %v", err)
	}
	if n := cfg.CallCount("PutDeliveryChannel"); n != 0 {
		t.Errorf("PutDeliveryChannel called %d times on an unchanged re-run, want 0", n)
	}
	if action == nil || action.Verb != org.VerbUnchanged || action.Applied {
		t.Fatalf("want one unchanged, unapplied action, got %+v", action)
	}
}

// TestEnsureDeliveryChannelDriftTriggersUpdate confirms a channel already
// pointed at a DIFFERENT bucket than spec now describes is repointed.
func TestEnsureDeliveryChannelDriftTriggersUpdate(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	if _, err := e.EnsureDeliveryChannel(ctx(),
		envprofile.ConfigRecorder{Enabled: true, DeliveryBucket: "old-bucket"}); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	cfg.Reset()

	action, err := e.EnsureDeliveryChannel(ctx(),
		envprofile.ConfigRecorder{Enabled: true, DeliveryBucket: testDeliveryBucket})
	if err != nil {
		t.Fatalf("EnsureDeliveryChannel: %v", err)
	}
	if n := cfg.CallCount("PutDeliveryChannel"); n != 1 {
		t.Errorf("PutDeliveryChannel called %d times, want 1", n)
	}
	if action == nil || action.Verb != org.VerbUpdate || !action.Applied {
		t.Fatalf("want one applied update action, got %+v", action)
	}
	if got := *cfg.DeliveryChannels["default"].S3BucketName; got != testDeliveryBucket {
		t.Errorf("delivery channel S3BucketName = %q, want %q", got, testDeliveryBucket)
	}
}

// TestEnsureDeliveryChannelParksOnPutDenial is BP.CFG-2's own Q13-shaped
// scenario, mirroring EnsureConfigRecorder's own PutConfigurationRecorder
// test.
func TestEnsureDeliveryChannelParksOnPutDenial(t *testing.T) {
	e, cfg := newConfigFixtureEnsurer(org.ModeApply)
	cfg.PutDeliveryChannelErr = awsfake.AccessDenied("config:PutDeliveryChannel")

	_, err := e.EnsureDeliveryChannel(ctx(), envprofile.ConfigRecorder{Enabled: true, DeliveryBucket: testDeliveryBucket})
	if err == nil {
		t.Fatal("want an error when PutDeliveryChannel is denied")
	}
	if !org.Parkable(err) {
		t.Errorf("this denial must be org.Parkable so `vend` parks rather than fails outright: %v", err)
	}
	if !strings.Contains(err.Error(), "baseline-protection") {
		t.Errorf("error does not mention baseline-protection (BP.CFG-2): %v", err)
	}
}
