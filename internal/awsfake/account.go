// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Account fakes awsapi.AccountAPI: opt-in region enablement for an
// environment profile's envprofile.BaselineRegions, performed in-child during
// baselining (internal/baseline, not yet built).
//
// Regions holds every region's current opt-in status, keyed by region code.
// Seeded by NewAccount with AWS's own always-on regions
// (Enabled_By_Default) so a test starts from a realistic account rather than
// one with no regions at all — a real account never has zero regions listed.
type Account struct {
	Recorder

	Regions map[string]accounttypes.RegionOptStatus

	// EnablePollsLeft/DisablePollsLeft mirror ConfigAPI's StatusPollsLeft: how
	// many GetRegionOptStatus calls report the transitional state (ENABLING /
	// DISABLING) before landing on the terminal one, per region code. A region
	// absent from either map lands on the terminal state on the first poll.
	EnablePollsLeft  map[string]int
	DisablePollsLeft map[string]int

	// Per-method error injection, following the naming convention the other
	// fakes in this package use.
	ListRegionsErr        error
	EnableRegionErr       error
	DisableRegionErr      error
	GetRegionOptStatusErr error
}

// NewAccount returns an Account fake seeded with AWS's set of regions that
// are enabled by default and cannot be disabled — every account has these
// regardless of any EnableRegion/DisableRegion call, which is the baseline a
// test diffs against to see what baseline.regions actually changed.
func NewAccount() *Account {
	a := &Account{
		Regions:          map[string]accounttypes.RegionOptStatus{},
		EnablePollsLeft:  map[string]int{},
		DisablePollsLeft: map[string]int{},
	}
	for _, r := range []string{"us-east-1", "us-west-2", "eu-west-1"} {
		a.Regions[r] = accounttypes.RegionOptStatusEnabledByDefault
	}
	return a
}

// ListRegions implements awsapi.AccountAPI.
//
// Filtered by RegionOptStatusContains when the caller sets it, matching the
// real API — the read-first half a future baseline.EnsureRegions needs to
// decide which of baseline.regions.enable are already on and which of
// baseline.regions.disable are already off, the same "read decides whether
// the write is a no-op" shape org.EnsureSCPEnabled uses ListRoots for.
func (f *Account) ListRegions(_ context.Context, in *account.ListRegionsInput,
	_ ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	f.Record("ListRegions")
	if f.ListRegionsErr != nil {
		return nil, f.ListRegionsErr
	}
	var want map[accounttypes.RegionOptStatus]bool
	if len(in.RegionOptStatusContains) > 0 {
		want = map[accounttypes.RegionOptStatus]bool{}
		for _, s := range in.RegionOptStatusContains {
			want[s] = true
		}
	}
	var names []string
	for name := range f.Regions {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]accounttypes.Region, 0, len(names))
	for _, name := range names {
		status := f.Regions[name]
		if want != nil && !want[status] {
			continue
		}
		out = append(out, accounttypes.Region{RegionName: aws.String(name), RegionOptStatus: status})
	}
	return &account.ListRegionsOutput{Regions: out}, nil
}

// EnableRegion implements awsapi.AccountAPI.
//
// Refuses a region that is already enabled or enabled-by-default the way the
// real API does — AWS returns a validation-shaped error for a redundant
// enable rather than treating it as a no-op, and an ensure operation has to
// read ListRegions first specifically so this branch is never exercised on a
// re-run, the same discipline org.EnsureSCPEnabled's own doc comment
// describes for a second EnablePolicyType.
func (f *Account) EnableRegion(_ context.Context, in *account.EnableRegionInput,
	_ ...func(*account.Options)) (*account.EnableRegionOutput, error) {
	f.Record("EnableRegion")
	if f.EnableRegionErr != nil {
		return nil, f.EnableRegionErr
	}
	name := aws.ToString(in.RegionName)
	switch f.Regions[name] {
	case accounttypes.RegionOptStatusEnabled, accounttypes.RegionOptStatusEnabledByDefault,
		accounttypes.RegionOptStatusEnabling:
		return nil, &APIError{
			Code:    "ConflictException",
			Message: "The Region " + name + " is already enabled or enabling.",
		}
	}
	f.Regions[name] = accounttypes.RegionOptStatusEnabling
	return &account.EnableRegionOutput{}, nil
}

// DisableRegion implements awsapi.AccountAPI.
//
// Refuses a region that is enabled-by-default: AWS does not allow disabling
// those (the "cannot be disabled" half of RegionOptStatusEnabledByDefault's
// own meaning), which is exactly the account.go doc comment's point about
// this interface's absent alternate-contact/billing surface having a
// different, unrelated shape of "not automat's problem" — this refusal IS
// automat's problem, because a profile that named one of these regions in
// baseline.regions.disable would otherwise appear to succeed and silently
// leave the region on.
func (f *Account) DisableRegion(_ context.Context, in *account.DisableRegionInput,
	_ ...func(*account.Options)) (*account.DisableRegionOutput, error) {
	f.Record("DisableRegion")
	if f.DisableRegionErr != nil {
		return nil, f.DisableRegionErr
	}
	name := aws.ToString(in.RegionName)
	switch f.Regions[name] {
	case accounttypes.RegionOptStatusEnabledByDefault:
		return nil, &APIError{
			Code:    "ConflictException",
			Message: "The Region " + name + " is enabled by default and cannot be disabled.",
		}
	case accounttypes.RegionOptStatusDisabled, accounttypes.RegionOptStatusDisabling:
		return nil, &APIError{
			Code:    "ConflictException",
			Message: "The Region " + name + " is already disabled or disabling.",
		}
	}
	f.Regions[name] = accounttypes.RegionOptStatusDisabling
	return &account.DisableRegionOutput{}, nil
}

// GetRegionOptStatus implements awsapi.AccountAPI.
//
// The poll target for both EnableRegion and DisableRegion's async
// completion — region enablement takes "a few minutes... [or] several hours"
// per EnableRegionInput's own doc comment, the same "accepted, not finished"
// shape OrgVendAPI.DescribeCreateAccountStatus and
// ConfigAPI.DescribeConformancePackStatus already poll for their own
// operations. EnablePollsLeft/DisablePollsLeft gate how many transitional
// answers precede the terminal one, per region.
func (f *Account) GetRegionOptStatus(_ context.Context, in *account.GetRegionOptStatusInput,
	_ ...func(*account.Options)) (*account.GetRegionOptStatusOutput, error) {
	f.Record("GetRegionOptStatus")
	if f.GetRegionOptStatusErr != nil {
		return nil, f.GetRegionOptStatusErr
	}
	name := aws.ToString(in.RegionName)
	status, ok := f.Regions[name]
	if !ok {
		return nil, &APIError{
			Code:    "ValidationException",
			Message: "The Region " + name + " is not a valid Region.",
		}
	}
	switch status {
	case accounttypes.RegionOptStatusEnabling:
		if left := f.EnablePollsLeft[name]; left > 0 {
			f.EnablePollsLeft[name] = left - 1
		} else {
			status = accounttypes.RegionOptStatusEnabled
			f.Regions[name] = status
		}
	case accounttypes.RegionOptStatusDisabling:
		if left := f.DisablePollsLeft[name]; left > 0 {
			f.DisablePollsLeft[name] = left - 1
		} else {
			status = accounttypes.RegionOptStatusDisabled
			f.Regions[name] = status
		}
	}
	return &account.GetRegionOptStatusOutput{
		RegionName:      aws.String(name),
		RegionOptStatus: status,
	}, nil
}

var _ awsapi.AccountAPI = (*Account)(nil)
