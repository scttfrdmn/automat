// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/org"
)

// regionListPageCap bounds ListRegions' pagination loop, mirroring
// internal/org's own listPageCap and for the identical reason: a stop against
// a service that returns the same NextToken forever, or a fake with a paging
// bug, rather than a real AWS quota.
const regionListPageCap = 500

// EnsureRegions makes an account's opt-in region set match spec —
// envprofile.BaselineRegions, DESIGN §7 step 5's opt-in region enablement
// (ROADMAP's "internal/baseline, slices 2-9", item 5).
//
// Read-first, the same discipline every other Ensure method in this package
// and internal/org.Ensurer follows: ListRegions decides which of spec.Enable
// are already on and which of spec.Disable are already off, so a re-vend
// issues no write for a region already in the wanted state (CLAUDE.md rule
// 4). Idempotent for the same reason EnsureAutomationRole is: a second call
// against an unchanged desired state reports VerbUnchanged everywhere and
// writes nothing.
//
// # spec.Home is informational only in this pass
//
// There is no AWS API to change an account's home (creation) region after
// the fact, so spec.Home drives no call here at all — it is a fact for a
// future `verify` region-layer check to read and cross-check, not something
// this Ensure step can act on. Skipped rather than recorded as an action:
// recording an unchanged action for a field this method never even reads
// would suggest a check happened when none did.
//
// # The ENABLED_BY_DEFAULT refusal is plan-time, not a raw AWS error
//
// A region AWS enables by default for every account
// (accounttypes.RegionOptStatusEnabledByDefault) can never be disabled via
// DisableRegion — not a quota, not a permission, a property of the region
// itself. If spec.Disable names one, this is refused before any write is
// attempted, with remediation naming the exact field to fix, rather than
// let a caller reach DisableRegion and get back an undifferentiated
// ConflictException. The check runs after the same ListRegions read every
// other branch uses, so it applies equally whether e.Mode is plan or apply —
// a plan that would fail this way at apply time is exactly what a plan
// exists to catch first.
func (e *Ensurer) EnsureRegions(ctx context.Context, spec envprofile.BaselineRegions) ([]org.Action, error) {
	before := len(e.actions)
	if e.Account == nil {
		return nil, fmt.Errorf("cannot ensure region enablement: this Ensurer has no Account " +
			"Management client")
	}
	if len(spec.Enable) == 0 && len(spec.Disable) == 0 {
		// Nothing to enable or disable. spec.Home may still be set, but see the
		// method doc: there is no call this step could make for it either way.
		return nil, nil
	}

	current, err := e.listRegionStatus(ctx)
	if err != nil {
		return nil, err
	}

	var refused []string
	for _, name := range spec.Disable {
		if current[name] == accounttypes.RegionOptStatusEnabledByDefault {
			refused = append(refused, name)
		}
	}
	if len(refused) > 0 {
		return append([]org.Action(nil), e.actions[before:]...), fmt.Errorf(
			"baseline.regions.disable names %s, which AWS enables by default for every account and "+
				"does not allow disabling — not a quota or a permission, a property of the region "+
				"itself. Remove %s from baseline.regions.disable; there is no grant or retry that "+
				"changes this", strings.Join(refused, ", "), strings.Join(refused, ", "))
	}

	for _, name := range spec.Enable {
		if err := e.ensureRegionEnabled(ctx, name, current[name]); err != nil {
			return append([]org.Action(nil), e.actions[before:]...), err
		}
	}
	for _, name := range spec.Disable {
		if err := e.ensureRegionDisabled(ctx, name, current[name]); err != nil {
			return append([]org.Action(nil), e.actions[before:]...), err
		}
	}
	return append([]org.Action(nil), e.actions[before:]...), nil
}

// listRegionStatus reads every region's current opt-in status, paginating
// with the same NextToken discipline internal/org's own list loops use
// (dedupe by name, stop rather than loop on a repeated token).
func (e *Ensurer) listRegionStatus(ctx context.Context) (map[string]accounttypes.RegionOptStatus, error) {
	out := map[string]accounttypes.RegionOptStatus{}
	var token *string
	seen := map[string]bool{}
	for i := 0; i < regionListPageCap; i++ {
		page, err := e.Account.ListRegions(ctx, &account.ListRegionsInput{NextToken: token})
		if err != nil {
			return nil, awsapi.Denied(err, "account:ListRegions", "the account", e.Principal,
				grantSentence("account:ListRegions", "the account", e.Principal))
		}
		for _, r := range page.Regions {
			out[aws.ToString(r.RegionName)] = r.RegionOptStatus
		}
		next := aws.ToString(page.NextToken)
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return nil, fmt.Errorf("listing regions: the same pagination token came back twice, so " +
				"the list does not terminate; automat stopped rather than looping")
		}
		seen[next] = true
		token = page.NextToken
	}
	return nil, fmt.Errorf("listing regions did not reach the end of the list within %d pages; "+
		"automat stopped rather than looping", regionListPageCap)
}

// ensureRegionEnabled makes one region ENABLED, given its status as of the
// read EnsureRegions already did.
func (e *Ensurer) ensureRegionEnabled(ctx context.Context, name string, status accounttypes.RegionOptStatus) error {
	switch status {
	case accounttypes.RegionOptStatusEnabled, accounttypes.RegionOptStatusEnabledByDefault,
		accounttypes.RegionOptStatusEnabling:
		e.record(org.Action{
			Verb: org.VerbUnchanged, Kind: "region", Name: name,
			Detail: "already " + strings.ToLower(string(status)),
		})
		return nil
	}

	if e.planning() {
		e.record(org.Action{
			Verb: org.VerbEnable, Kind: "region", Name: name,
			Detail: "would be enabled; AWS reports this can take from minutes to hours to complete",
		})
		return nil
	}

	if _, err := e.Account.EnableRegion(ctx, &account.EnableRegionInput{RegionName: aws.String(name)}); err != nil {
		return awsapi.Denied(err, "account:EnableRegion", name, e.Principal,
			grantSentence("account:EnableRegion", name, e.Principal))
	}
	if err := e.pollRegionOptStatus(ctx, name, "enabling"); err != nil {
		return err
	}
	e.record(org.Action{
		Verb: org.VerbEnable, Kind: "region", Name: name, Detail: "enabled", Applied: true,
	})
	return nil
}

// ensureRegionDisabled makes one region DISABLED, given its status as of the
// read EnsureRegions already did. EnsureRegions has already refused any
// region reported ENABLED_BY_DEFAULT before this is ever called (see the
// method doc), so the only statuses this function can see are the ones that
// are actually disableable.
func (e *Ensurer) ensureRegionDisabled(ctx context.Context, name string, status accounttypes.RegionOptStatus) error {
	switch status {
	case accounttypes.RegionOptStatusDisabled, accounttypes.RegionOptStatusDisabling:
		e.record(org.Action{
			Verb: org.VerbUnchanged, Kind: "region", Name: name,
			Detail: "already " + strings.ToLower(string(status)),
		})
		return nil
	}

	if e.planning() {
		e.record(org.Action{
			Verb: org.VerbUpdate, Kind: "region", Name: name,
			Detail: "would be disabled; AWS reports this can take from minutes to hours to complete",
		})
		return nil
	}

	if _, err := e.Account.DisableRegion(ctx, &account.DisableRegionInput{RegionName: aws.String(name)}); err != nil {
		return awsapi.Denied(err, "account:DisableRegion", name, e.Principal,
			grantSentence("account:DisableRegion", name, e.Principal))
	}
	if err := e.pollRegionOptStatus(ctx, name, "disabling"); err != nil {
		return err
	}
	e.record(org.Action{
		Verb: org.VerbUpdate, Kind: "region", Name: name, Detail: "disabled", Applied: true,
	})
	return nil
}

// pollRegionOptStatus waits for a region's EnableRegion/DisableRegion call to
// reach a terminal state (ENABLED or DISABLED), the same "accepted, not
// finished" shape internal/org.Ensurer's own pollCreate uses for
// CreateAccount and the reason this package's Ensurer carries the identical
// PollInterval/MaxPolls/Sleep fields.
func (e *Ensurer) pollRegionOptStatus(ctx context.Context, name, action string) error {
	for i := 0; i < e.maxPolls(); i++ {
		out, err := e.Account.GetRegionOptStatus(ctx, &account.GetRegionOptStatusInput{RegionName: aws.String(name)})
		if err != nil {
			return awsapi.Denied(err, "account:GetRegionOptStatus", name, e.Principal,
				grantSentence("account:GetRegionOptStatus", name, e.Principal))
		}
		switch out.RegionOptStatus {
		case accounttypes.RegionOptStatusEnabled, accounttypes.RegionOptStatusDisabled:
			return nil
		}
		if serr := e.sleep(ctx, e.pollInterval()); serr != nil {
			return fmt.Errorf("waiting for region %s to finish %s: %w — the request is still in "+
				"flight at AWS and may yet succeed; re-run rather than assuming it failed",
				name, action, serr)
		}
	}
	return fmt.Errorf("region %s did not finish %s within %s. The request is still in flight at AWS "+
		"and may yet succeed; re-run rather than assuming it failed",
		name, action, time.Duration(e.maxPolls())*e.pollInterval())
}
