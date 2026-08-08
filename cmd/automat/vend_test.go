// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/evidence"
)

// vendWrites is every mutating Organizations call a vend can make.
//
// Written out rather than derived, for the same reason initWrites is: a test that
// asks "did --dry-run write anything" has to know the whole set, and a set computed
// from the code under test would agree with a bug.
var vendWrites = []string{
	"CreateAccount",
	"MoveAccount",
	"CreateOrganizationalUnit",
	"TagResource",
	"UntagResource",
	"CreatePolicy",
	"UpdatePolicy",
	"AttachPolicy",
	"DetachPolicy",
	"DeletePolicy",
	"EnablePolicyType",
	"CreateOrganization",
}

// vendWritesSeen returns the mutating calls that reached any fake.
//
// All three write fakes, not just the vend one: the point of the assertion is that
// nothing anywhere was mutated, and a vend that reached CreatePolicy would do it
// through the policy fake, which writesSeen's two-fake loop does not read.
func vendWritesSeen(f *fakeWorld) []string {
	var seen []string
	for _, r := range []interface {
		CallCount(string) int
	}{f.Init, f.Vend, f.Policy} {
		for _, op := range vendWrites {
			if n := r.CallCount(op); n > 0 {
				seen = append(seen, op)
			}
		}
	}
	return seen
}

// vendProfileJSON is a complete, valid environment profile.
//
// Built here rather than loaded from a shared fixture because most of these tests
// need one field different, and a fixture with a knob per test is a fixture nobody
// can read. The shape is internal/envprofile's own sample profile minus the pieces
// this package cannot supply — no signatures, because an unsigned profile is valid
// and a signed one would have to be stamped with a real key.
//
// Note which obligation is named. `dfars-7012`'s revision policy is `pinned`, so a
// reference to it must NOT carry a revision determination; `nih-cadr-dua` is
// `operator-determined`, so a reference to it must. Getting that backwards is a
// refusal from CheckObligations, which is exactly the honest behavior — but it would
// make every test in this file fail for the wrong reason.
func vendProfileJSON(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	doc := map[string]any{
		"schema_version": "1.0.0",
		"environment_profile": map[string]any{
			"id":          "research-cui",
			"title":       "Research CUI environment",
			"description": "Vends accounts rated to hold CUI under a departmental award.",
		},
		"review_by":    "2027-06-30",
		"control_sets": []any{"cmmc-l1"},
		"permitted": map[string]any{
			"regions":  []any{"us-east-1", "us-west-2"},
			"services": []any{"batch", "s3"},
		},
		"obligations": []any{
			map[string]any{"id": "dfars-7012", "content_sha256": strings.Repeat("a", 64)},
		},
		"placement": map[string]any{
			"target_ou": testVendOU,
		},
		"account": map[string]any{
			"email_pattern":              "research-admin+{name}@dept.example.edu",
			"role_name":                  "OrganizationAccountAccessRole",
			"iam_user_access_to_billing": "DENY",
		},
		"baseline": map[string]any{
			"config_recorder": map[string]any{"enabled": true},
		},
	}
	if mutate != nil {
		mutate(doc)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal the environment profile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write the environment profile: %v", err)
	}
	return path
}

// testVendOU is the OU a vend places accounts into. Seeded with a fixed id so the
// profile document can name it, which is what a real profile does.
const testVendOU = "ou-exam-vendtest1"

// packageDir is where this test file lives, captured before any test can chdir.
//
// Necessary because a vend writes its evidence manifest to a RELATIVE path — the
// profile's baseline.evidence.local_dir is relative to wherever the operator ran
// automat — so every applying test moves into a temp directory. Golden files must
// still be read from and written to the package's own testdata, and the first version
// of this helper used a relative path: AUTOMAT_UPDATE_GOLDEN=1 reported success and
// wrote the file into a temp directory that was then deleted.
var packageDir = func() string {
	wd, err := os.Getwd()
	if err != nil {
		panic("cannot determine the package directory: " + err.Error())
	}
	return wd
}()

// vendWorld is a management-account world with the destination OU already present,
// which is the state `automat init` leaves behind.
//
// evidenceDir is where the manifest lands. The profile does not name one, so the
// manifest goes to the schema default ("evidence") relative to the working
// directory — so every test that applies has to chdir into a temp directory, or the
// test run would write into the repository.
func vendWorld(t *testing.T) (*globals, *fakeWorld) {
	t.Helper()
	g, f := fakeSet(t, testOrg, testManagement, testManagement, simulatedVendActions...)
	f.State.SeedOUWithID(testVendOU, "Research CUI", f.State.RootID)
	f.Org.AddOU(testVendOU, "Research CUI", f.Org.RootID)
	chdirTemp(t)
	return g, f
}

// chdirTemp moves the process into a temp directory for the test's duration.
//
// t.Chdir rather than os.Chdir: it restores the old directory and, more usefully,
// makes the test fail rather than silently corrupt a parallel one if it is ever
// marked t.Parallel(). The evidence manifest's path is relative by design — the
// profile's baseline.evidence.local_dir is relative to wherever the operator ran
// automat — so a test that applies writes a real file, and this is where it goes.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

// vendArgs is the common flag set.
func vendArgs(profilePath string, extra ...string) []string {
	return append([]string{
		"vend",
		"--environment-profile", profilePath,
		"--name", "Genomics",
	}, extra...)
}

// TestVendRunTwiceChangesNothingTheSecondTime is CLAUDE.md rule 4 for the command
// that has the most to be idempotent about.
//
// The account, the OU placement, and every service control policy are all
// create-or-verify, so the second run must reach no mutating call at all and must
// say so. This is the assertion that would catch the whole class of bug where a
// vend re-created a policy because it compared a canonicalized document against a
// raw one, or created a second account because it searched the wrong parent.
//
// It also pins the thing an operator will actually do: re-run a vend after fixing
// something, without --resume, and not get a second account.
func TestVendRunTwiceChangesNothingTheSecondTime(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	firstOut, _, err := runCLI(t, g, vendArgs(profile)...)
	if err != nil {
		t.Fatalf("first vend: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("first vend produced %d accounts, want 1: %v", len(accounts), accounts)
	}
	accountID := accounts[0]
	if got := f.State.ParentOf(accountID); got != testVendOU {
		t.Fatalf("account %s is under %s, want %s", accountID, got, testVendOU)
	}
	if !strings.Contains(firstOut, "Birth certificate:") {
		t.Fatalf("the first vend printed no birth certificate:\n%s", firstOut)
	}

	before := map[string]int{}
	for _, op := range vendWrites {
		before[op] = f.Vend.CallCount(op) + f.Policy.CallCount(op)
	}

	secondOut, _, err := runCLI(t, g, vendArgs(profile)...)
	if err != nil {
		t.Fatalf("second vend: %v", err)
	}
	for _, op := range vendWrites {
		if got := f.Vend.CallCount(op) + f.Policy.CallCount(op); got != before[op] {
			t.Errorf("second vend called %s %d more times; a re-run must change nothing",
				op, got-before[op])
		}
	}
	if got := f.State.AccountIDs(); len(got) != 1 {
		t.Fatalf("second vend produced %d accounts, want 1: %v", len(got), got)
	}
	if !strings.Contains(secondOut, "Nothing needed changing") {
		t.Errorf("the second vend did not say it changed nothing:\n%s", secondOut)
	}

	// And the manifest did not grow. An append-only chain that gained a record on
	// every no-op re-run would bury the records that mean something, which defeats
	// the document rather than corrupting it — so it needs its own assertion.
	m := loadVendManifest(t, accountID)
	first := len(m.Records)
	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("third vend: %v", err)
	}
	if again := loadVendManifest(t, accountID); len(again.Records) != first {
		t.Errorf("a no-op vend appended %d records to the manifest; it must append none",
			len(again.Records)-first)
	}
}

// TestVendNamesPackedPoliciesByProfileIdAndOrdinal is DESIGN §14's SCP naming
// convention, pinned so the packer or the call site cannot drift from it silently
// (Q16, docs/open-questions.md).
//
// A packed policy has no single artifact id and no single class — a vend unions
// multiple control sets into a shared statement pool before packing — so the name
// is automat-<environment-profile-id>-<n> rather than one naming an artifact or a
// class. The environment profile id is the one id a packed policy always has
// exactly one of.
func TestVendNamesPackedPoliciesByProfileIdAndOrdinal(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}

	names := f.State.PolicyNames()
	if len(names) == 0 {
		t.Fatal("vend attached no policies")
	}
	for i, name := range names {
		want := fmt.Sprintf("automat-research-cui-%d", i+1)
		if name != want {
			t.Errorf("policy %d is named %q, want %q — automat-<environment-profile-id>-<n>",
				i, name, want)
		}
	}
}

// TestVendDryRunWritesNothing.
//
// Two kinds of nothing, and both matter. No AWS mutation, which is what --dry-run
// says on the label. And no evidence manifest: a plan that left a manifest behind
// would put a record of an account that does not exist into the chain an auditor
// reads, and there is no way to tell later that it was only ever a plan.
func TestVendDryRunWritesNothing(t *testing.T) {
	g, f := vendWorld(t)
	dir := chdirTemp(t)
	profile := vendProfileJSON(t, nil)

	out, _, err := runCLI(t, g, vendArgs(profile, "--dry-run")...)
	if err != nil {
		t.Fatalf("vend --dry-run: %v", err)
	}
	if seen := vendWritesSeen(f); len(seen) > 0 {
		t.Errorf("--dry-run reached %v; it must reach no mutating call", seen)
	}
	if got := f.State.AccountIDs(); len(got) != 0 {
		t.Errorf("--dry-run created accounts %v", got)
	}
	if entries, rerr := os.ReadDir(filepath.Join(dir, "evidence")); rerr == nil {
		t.Errorf("--dry-run created an evidence directory holding %d entries; a plan is not "+
			"evidence", len(entries))
	}
	if !strings.Contains(out, "Nothing was applied (--dry-run).") {
		t.Errorf("--dry-run did not say nothing was applied:\n%s", out)
	}
	if !strings.Contains(out, "Plan:") {
		t.Errorf("--dry-run printed no plan:\n%s", out)
	}
	// The plan must also carry step 5's absence and the unknown policy set, because
	// the plan is the only thing a --dry-run operator sees.
	for _, want := range []string{
		"in-child baseline (DESIGN §7 step 5)",
		"the account does not exist yet",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan does not mention %q:\n%s", want, out)
		}
	}
}

// TestVendRefusesAnEmptyIntersectionAtPlanTime is Q14's E5.
//
// A profile permitting only regions the control sets do not permit intersects to
// nothing. An empty allowlist is not a strict policy but a deny-all — it denies
// every call in the account including automat's own baseline — so it must be refused
// rather than attached.
//
// What this test is really pinning is WHEN. The refusal has to arrive before any
// AWS call, because after create and move have succeeded the operator has an account
// they did not want and a refusal they cannot act on. So the assertion is not only
// on the message but on the fake having been untouched.
func TestVendRefusesAnEmptyIntersectionAtPlanTime(t *testing.T) {
	// The present-but-empty permitted set — the deny-all shape reachable with the
	// catalogs automat ships. See TestVendGoldenEmptyPermittedSetRefusal for why the
	// disjoint shape is golden in internal/compilesets instead.
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, func(doc map[string]any) {
		doc["permitted"] = map[string]any{"regions": []any{}}
	})

	_, _, err := runCLI(t, g, vendArgs(profile, "--dry-run")...)
	if err == nil {
		t.Fatal("a profile permitting no regions at all was accepted; an empty allowlist is a " +
			"deny-all and must be refused")
	}
	msg := err.Error()
	for _, want := range []string{"present but empty", "DENY-ALL"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if seen := vendWritesSeen(f); len(seen) > 0 {
		t.Errorf("the refusal arrived after %v had already been called; it must arrive at plan "+
			"time, before anything exists", seen)
	}
	if got := f.STS.CallCount("GetCallerIdentity"); got != 0 {
		t.Errorf("the refusal arrived after %d GetCallerIdentity calls; every document check "+
			"happens before a credential is even resolved", got)
	}
}

// TestVendGoldenEmptyPermittedSetRefusal pins the whole refusal text for the
// deny-all a vend can actually be handed.
//
// Golden because the message IS the feature (rule 7): an operator who narrowed a
// profile into a deny-all needs to be told what would happen and what to edit, and a
// message that degrades into "invalid configuration" over a few refactors is the
// failure a golden file exists to catch.
//
// # Why this case and not the disjoint one
//
// Q14's E5 has two shapes. The present-but-empty set is refused by
// envprofile.Validate; the profile-and-control-sets-disjoint intersection is refused
// by compilesets.Narrow. Only the first is reachable through the CLI with the
// catalogs automat ships, because neither `cmmc-l1` nor `baseline-protection` carries
// a region or service allowlist — so an intersection against a nil existing set is
// just the profile's own set, which is never empty. The disjoint shape is golden in
// internal/compilesets/testdata/refusals, next to the code that raises it and the
// hand-built Merged values that can reach it. Reaching it from here would mean
// pointing the command at a synthetic catalog tree, which is a flag the CLI does not
// have and should not gain for a test.
//
// What this DOES pin at plan time, and it is the property that matters: the refusal
// arrives from a document check, before a credential is resolved or an account
// exists. TestVendRefusesAnEmptyIntersectionAtPlanTime asserts that half.
func TestVendGoldenEmptyPermittedSetRefusal(t *testing.T) {
	g, _ := vendWorld(t)
	profile := vendProfileJSON(t, func(doc map[string]any) {
		doc["permitted"] = map[string]any{
			"regions":  []any{"us-east-1"},
			"services": []any{},
		}
	})

	_, _, err := runCLI(t, g, vendArgs(profile, "--dry-run")...)
	if err == nil {
		t.Fatal("an empty permitted-service set was accepted")
	}
	// The profile's path leads the message, and it is a fresh temp directory every
	// run. Redacted rather than dropped: an error that did not name the file an
	// operator has to edit would be a worse error, so the golden has to show that it
	// is there.
	assertGolden(t, "vend-empty-permitted-set.txt",
		strings.Replace(err.Error(), profile, "<profile path>", 1))
}

// TestVendParksWhenAPolicyFailsAfterTheAccountExists is ROADMAP Phase 2's fourth
// case, and the one with teeth.
//
// The account was created and moved; the policy attach was denied. That state must
// not abort as an ordinary error, because the wrong next step — a fresh `vend`
// whose first act is CreateAccount — is also the obvious one. So four things have to
// hold at once: the account survives, the manifest records it, the error says PARKED
// and names what continues it, and nothing tries to undo the account.
func TestVendParksWhenAPolicyFailsAfterTheAccountExists(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	f.State.Errs["CreatePolicy"] = awsfake.AccessDenied("organizations:CreatePolicy")

	_, stderr, err := runCLI(t, g, vendArgs(profile)...)
	if err == nil {
		t.Fatal("a denied CreatePolicy after a successful create and move returned no error")
	}
	msg := err.Error()

	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("the parked vend left %d accounts, want the 1 it created: %v",
			len(accounts), accounts)
	}
	accountID := accounts[0]
	if got := f.State.ParentOf(accountID); got != testVendOU {
		t.Errorf("the parked vend left account %s under %s; the move had already succeeded and "+
			"must not be undone", accountID, got)
	}
	if got := f.Vend.CallCount("CreateAccount"); got != 1 {
		t.Errorf("CreateAccount was called %d times, want 1", got)
	}

	if !strings.Contains(msg, "PARKED") {
		t.Errorf("the error does not say the vend is parked:\n%s", msg)
	}
	if !strings.Contains(msg, accountID) {
		t.Errorf("the error does not name account %s, which exists:\n%s", accountID, msg)
	}
	if !strings.Contains(msg, "organizations:CreatePolicy") {
		t.Errorf("the error does not name the denied action (rule 7):\n%s", msg)
	}
	if !strings.Contains(stderr, "Applied before the failure:") {
		t.Errorf("the partial-progress report did not reach stderr:\n%s", stderr)
	}

	// The manifest is the durable half of parking. It must exist, chain-validate,
	// and carry a parked record whose remediation is a command.
	m := loadVendManifest(t, accountID)
	if len(m.Parked()) == 0 {
		t.Errorf("the manifest for a parked vend reports no parked records")
	}
	var parked *evidence.Record
	for i := range m.Records {
		if m.Records[i].Operation == evidence.OpSCPEnsure &&
			m.Records[i].Outcome == evidence.OutcomeParked {
			parked = &m.Records[i]
		}
	}
	if parked == nil {
		t.Fatalf("the manifest carries no parked scp-ensure record: %+v", m.Records)
	}
	if parked.Err == nil || parked.Err.Message == "" {
		t.Fatalf("the parked record carries no error; evidence requires one")
	}
	if !strings.Contains(parked.Err.Remediation, "automat vend") &&
		!strings.Contains(parked.Err.Remediation, "--resume") &&
		!strings.Contains(parked.Err.Remediation, "re-run") {
		t.Errorf("the parked record's remediation is not an action: %q", parked.Err.Remediation)
	}

	// And the resume works: clearing the denial and re-running finishes the vend
	// against the same account rather than creating a second one.
	delete(f.State.Errs, "CreatePolicy")
	if _, _, rerr := runCLI(t, g, vendArgs(profile)...); rerr != nil {
		t.Fatalf("the re-run after clearing the denial failed: %v", rerr)
	}
	if got := f.State.AccountIDs(); len(got) != 1 {
		t.Fatalf("the re-run produced %d accounts, want 1: %v", len(got), got)
	}
	if len(f.State.AttachedTo(testVendOU)) == 0 {
		t.Errorf("the re-run attached no policy to %s; parking must be resumable, not just "+
			"survivable", testVendOU)
	}
}

// TestVendManifestChainValidates.
//
// The hash chain is the product. Every record's previous_sha256 must be the
// preceding record's record_sha256, and VerifyChain is what says so — over the
// manifest as it was written to disk and read back, not over the in-memory value,
// because a canonicalization difference between write and read is precisely the bug
// that would make an auditor's verification fail on a manifest automat considers
// fine.
func TestVendManifestChainValidates(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("want 1 account, got %v", accounts)
	}
	accountID := accounts[0]

	m := loadVendManifest(t, accountID)
	// A nil verifier: the manifest is unsigned, because automat ships no key
	// ceremony (DESIGN §11a) and there is no signing-key setting for the command to
	// read. VerifyChain still checks every hash and every link, which is the part
	// that is automat's to get right.
	if err := m.VerifyChain(nil); err != nil {
		t.Fatalf("the manifest automat just wrote does not verify: %v", err)
	}
	if len(m.Records) == 0 {
		t.Fatal("the manifest holds no records")
	}
	if m.Meta.AccountID != accountID {
		t.Errorf("manifest account_id is %q, want %q", m.Meta.AccountID, accountID)
	}
	if m.Meta.OrganizationID != testOrg {
		t.Errorf("manifest organization_id is %q, want %q", m.Meta.OrganizationID, testOrg)
	}

	ops := map[evidence.Operation]bool{}
	for _, r := range m.Records {
		ops[r.Operation] = true
		if r.EnvProfile == nil || r.EnvProfile.ID != "research-cui" {
			t.Errorf("record %d does not attest to the environment profile: %+v", r.Sequence,
				r.EnvProfile)
		}
		if r.EnvProfile != nil && len(r.EnvProfile.VerifiedSignatures) != 0 {
			t.Errorf("record %d claims verified signatures; the profile carried none",
				r.Sequence)
		}
	}
	for _, want := range []evidence.Operation{
		evidence.OpAccountCreate,
		evidence.OpAccountMove,
		evidence.OpSCPEnsure,
		// The one that must be present precisely because the work was NOT done.
		evidence.OpBaselineApply,
	} {
		if !ops[want] {
			t.Errorf("the manifest carries no %s record: %v", want, ops)
		}
	}

	// The baseline record is parked, not successful, and that is the honesty gate
	// for this whole commit: a manifest with account-create and scp-ensure and no
	// baseline-apply reads as a baseline that happened.
	for _, r := range m.Records {
		if r.Operation != evidence.OpBaselineApply {
			continue
		}
		if r.Outcome != evidence.OutcomeParked {
			t.Errorf("the baseline-apply record's outcome is %q; this build performs no in-child "+
				"baseline work, so it must be parked", r.Outcome)
		}
		if r.Err == nil || !strings.Contains(r.Err.Message, "step 5") {
			t.Errorf("the baseline-apply record does not say which step was skipped: %+v", r.Err)
		}
	}

	// The enforcement summary names the policies as ARNs, not ids.
	var enforced *evidence.Enforcement
	for i := range m.Records {
		if m.Records[i].Enforcement != nil {
			enforced = m.Records[i].Enforcement
		}
	}
	if enforced == nil {
		t.Fatal("no record carries an enforcement summary")
	}
	for _, arn := range enforced.SCPARNs {
		if !strings.HasPrefix(arn, "arn:aws:organizations::") {
			t.Errorf("scp_arns holds %q, which is not an Organizations policy ARN", arn)
		}
	}
	if len(enforced.RegionSet) == 0 && len(enforced.ServiceSet) == 0 {
		t.Errorf("the enforcement summary records neither a region nor a service set, but the "+
			"profile constrained both: %+v", enforced)
	}
}

// TestVendRefusesToVendIntoARootWithSCPsDisabled.
//
// org.SCPEnabled's doc calls this "the one failure in this package that produces a
// green run and an unprotected account": with the policy type off, CreatePolicy and
// AttachPolicy both succeed and nothing is enforced. It is also the state a
// hand-prepared organization is often in, so the refusal has to come before the
// account exists rather than after.
func TestVendRefusesToVendIntoARootWithSCPsDisabled(t *testing.T) {
	g, f := vendWorld(t)
	f.Org.SCPStatus = ""
	profile := vendProfileJSON(t, nil)

	_, _, err := runCLI(t, g, vendArgs(profile)...)
	if err == nil {
		t.Fatal("vending into a root with the service control policy type disabled succeeded; " +
			"that is a green run and an unprotected account")
	}
	if !strings.Contains(err.Error(), "not ENABLED") {
		t.Errorf("the refusal does not say the policy type is not enabled:\n%s", err)
	}
	if !strings.Contains(err.Error(), "automat init") {
		t.Errorf("the refusal does not say how to fix it (rule 7):\n%s", err)
	}
	if got := f.State.AccountIDs(); len(got) != 0 {
		t.Errorf("the refusal arrived after creating %v; it must arrive first", got)
	}
}

// TestVendTagsTheAccountForTheConditionsThatReadThem.
//
// automat:vended-by and automat:ou are not labels. The vendor role's CreateAccount
// grant requires both as request tags and its MoveAccount grant requires vended-by
// on the account (internal/bundle/role.go), so they can only be set at creation —
// a tag a condition reads must not be writable by the principal the condition
// constrains. vended-by is the VENDING account's id, which is what makes an account
// attributable.
//
// RequiredCreateTags is the knob that makes this a real test rather than an
// assertion about a map: the fake fails CreateAccount with AccessDenied when a
// required tag is missing, mimicking the grant.
func TestVendTagsTheAccountForTheConditionsThatReadThem(t *testing.T) {
	g, f := vendWorld(t)
	f.State.RequiredCreateTags = []string{"automat:vended-by", "automat:ou"}
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend with the grant's required tags enforced: %v", err)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("want 1 account, got %v", accounts)
	}
	tags := f.State.TagsOf(accounts[0])
	if got := tags["automat:vended-by"]; got != testManagement {
		t.Errorf("automat:vended-by is %q, want the vending account %q — not the vended one and "+
			"not the literal \"automat\"", got, testManagement)
	}
	if got := tags["automat:ou"]; got != testVendOU {
		t.Errorf("automat:ou is %q, want %q", got, testVendOU)
	}
}

// TestVendTagsTheDelegatedOUEvenWhenItPlacesDeeper is AUDIT-2's automat:ou finding.
//
// The vendor role renders the condition as a literal:
//
//	StringEquals: {aws:RequestTag/automat:ou: '<TargetOU>'}
//
// fixed when the bundle was generated (internal/bundle/role.go:170). vend used to
// tag with st.Destination, the OU it resolved placement.ou_path to — the same value
// until a profile sets ou_path, and a different one after. Every such vend was
// AccessDeniedException in a real organization, and the whole suite passed because
// awsfake compared tag KEYS and not values.
//
// So this test pins the value the way the grant does, and asserts the two things
// that must both hold and used to be conflated: the tag names the DELEGATED OU, and
// the account is placed in the NESTED one. Asserting only the tag would pass a
// regression that fixed the tag by refusing to descend.
func TestVendTagsTheDelegatedOUEvenWhenItPlacesDeeper(t *testing.T) {
	g, f := vendWorld(t)
	f.State.RequiredCreateTagValues = map[string]string{
		"automat:vended-by": testManagement,
		"automat:ou":        testVendOU,
	}
	profile := vendProfileJSON(t, func(doc map[string]any) {
		doc["placement"] = map[string]any{
			"target_ou":               testVendOU,
			"ou_path":                 []any{"Genomics"},
			"create_intermediate_ous": true,
		}
	})

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend into a nested OU with the grant's request-tag VALUES enforced: %v\n\n"+
			"An AccessDenied here is the finding, not a test bug: the grant admits only the "+
			"delegated OU %s in automat:ou, so tagging with the resolved placement OU is a "+
			"denial in any real organization.", err, testVendOU)
	}

	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("want 1 account, got %v", accounts)
	}
	if got := f.State.TagsOf(accounts[0])["automat:ou"]; got != testVendOU {
		t.Errorf("automat:ou is %q, want the delegated OU %q that the grant pins", got, testVendOU)
	}

	// And it still descended. The tag answers "under which delegation", ListParents
	// answers "where is it now", and the profile's ou_path governs the second.
	nested := ""
	for _, id := range f.State.OUIDsUnder(testVendOU) {
		if f.State.OUName(id) == "Genomics" {
			nested = id
		}
	}
	if nested == "" {
		t.Fatalf("no OU named Genomics below %s; the path was not created", testVendOU)
	}
	if got := f.State.ParentOf(accounts[0]); got != nested {
		t.Errorf("the account is under %s, want the nested OU %s — the tag names the "+
			"delegated OU, but placement must still honor ou_path", got, nested)
	}
}

// TestVendResumeContinuesRatherThanCreatingASecondAccount.
//
// --resume takes a create-account request id, and the whole reason it exists is that
// re-running a command whose first act is CreateAccount against an in-flight create
// would consume a second account from the organization's quota. So the assertion is
// the call count.
func TestVendResumeContinuesRatherThanCreatingASecondAccount(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("first vend: %v", err)
	}
	m := loadVendManifest(t, f.State.AccountIDs()[0])
	requestID := ""
	for _, r := range m.Records {
		if r.RequestID != "" {
			requestID = r.RequestID
		}
	}
	if requestID == "" {
		t.Fatal("the manifest recorded no create-account request id, so nothing could be resumed")
	}

	before := f.Vend.CallCount("CreateAccount")
	if _, _, err := runCLI(t, g, "vend",
		"--environment-profile", profile,
		"--resume", requestID,
		"--email", "research-admin+genomics@dept.example.edu",
	); err != nil {
		t.Fatalf("vend --resume %s: %v", requestID, err)
	}
	if got := f.Vend.CallCount("CreateAccount"); got != before {
		t.Errorf("--resume called CreateAccount %d more times; it must continue the existing "+
			"request", got-before)
	}
	if got := f.State.AccountIDs(); len(got) != 1 {
		t.Errorf("--resume produced %d accounts, want 1: %v", len(got), got)
	}
}

// TestTheBirthCertificateMarksAnUnretrievedCitation is AUDIT-2 F1.
//
// The birth certificate cites each obligation profile by id and content hash. Two of
// the three shipped profiles record their own citations from published identifiers
// rather than from retrieved copies — dfars-7012 is one, and it is the one the vend
// fixture references — so a certificate citing it by hash presents a traced claim
// where none was traced.
//
// The gate that was supposed to prevent this was a map literal inside a test function
// in another package, which no renderer could read and which, being empty, could not
// fail. This asserts the marking is in the RENDERED LINE, because
// docs/policy-caveat.md's argument is that the rendered output is what gets forwarded
// and attached to an agreement without the page that explained the caveat.
func TestTheBirthCertificateMarksAnUnretrievedCitation(t *testing.T) {
	g, _ := vendWorld(t)
	out, _, err := runCLI(t, g, vendArgs(vendProfileJSON(t, nil))...)
	if err != nil {
		t.Fatalf("vend: %v", err)
	}

	// The obligations line, isolated, so a marking that landed somewhere else in the
	// document does not satisfy this.
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "dfars-7012") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("the birth certificate does not cite dfars-7012 at all:\n%s", out)
	}
	for _, want := range []string{
		"CITATIONS NOT RETRIEVED",
		"primary source",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the obligations line does not contain %q, so it presents an untraced citation "+
				"as a traced one:\n%s", want, line)
		}
	}
}

// TestVendRefusesToResumeAnotherProfilesRequest is AUDIT-2's critical finding.
//
// The finding, stated as the attack: a create-account request id is printed on the
// birth certificate and recorded in the evidence manifest, precisely so an operator
// can type it back. It is not a secret and it never was one. Yet `--resume` used to
// treat it as sufficient on its own — AccountSpec.validate() short-circuited on
// RequestID and nothing compared the resumed status against anything the caller
// claimed. So a second operator, holding nothing but an id off a report, could resume
// somebody else's vend under their OWN environment profile, and `vend` would go on to
// call EnsurePlacement on that account. An account has exactly one parent, so the
// victim's account moves out from under every service control policy attached where it
// is now and into the attacker's target OU — and the victim's own manifest records the
// move as a success.
//
// The binding is the root email, not the account name: two accounts may share a name,
// which is the reason findAccountByEmail searches by email. So this asserts the
// refusal names BOTH addresses, and — the part that matters more — that the account
// did not move.
//
// TestVendResumeContinuesRatherThanCreatingASecondAccount above resumes with the SAME
// profile and email, which is precisely why it never caught this.
func TestVendRefusesToResumeAnotherProfilesRequest(t *testing.T) {
	g, f := vendWorld(t)
	victimProfile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(victimProfile)...); err != nil {
		t.Fatalf("the victim's vend: %v", err)
	}
	victimID := f.State.AccountIDs()[0]
	requestID := ""
	for _, r := range loadVendManifest(t, victimID).Records {
		if r.RequestID != "" {
			requestID = r.RequestID
		}
	}
	if requestID == "" {
		t.Fatal("the manifest recorded no create-account request id, so there is nothing to attack with")
	}
	parentBefore := f.State.ParentOf(victimID)
	if parentBefore == "" {
		t.Fatalf("the victim's account %s has no parent, so a move could not be detected", victimID)
	}

	// A second OU, and a profile that targets it. This is the attacker's own
	// legitimate profile in every respect except the request id they typed into it.
	attackerOU := "ou-atck-attacker1"
	f.State.SeedOUWithID(attackerOU, "Attacker", f.State.RootID)
	f.Org.AddOU(attackerOU, "Attacker", f.Org.RootID)
	attackerProfile := vendProfileJSON(t, func(doc map[string]any) {
		doc["environment_profile"].(map[string]any)["id"] = "attacker-profile"
		doc["placement"].(map[string]any)["target_ou"] = attackerOU
	})

	_, stderr, err := runCLI(t, g, "vend",
		"--environment-profile", attackerProfile,
		"--resume", requestID,
		"--email", "attacker+genomics@other.example.edu",
	)
	if err == nil {
		t.Fatalf("vend --resume accepted another profile's request id; the account is now under %s",
			f.State.ParentOf(victimID))
	}
	// Both addresses, so the operator can tell a typo from someone else's account.
	// The victim's address carries the name's own case: account.email_pattern
	// substitutes --name verbatim, and the comparison is what is case-insensitive,
	// not the recorded value.
	for _, want := range []string{
		"research-admin+Genomics@dept.example.edu",
		"attacker+genomics@other.example.edu",
		"exactly one parent",
	} {
		if !strings.Contains(stderr, want) && !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v\n%s", want, err, stderr)
		}
	}
	if got := f.State.ParentOf(victimID); got != parentBefore {
		t.Errorf("the victim's account moved from %s to %s despite the refusal", parentBefore, got)
	}
	if got := f.State.AccountIDs(); len(got) != 1 {
		t.Errorf("the refused resume produced %d accounts, want 1: %v", len(got), got)
	}
}

// TestVendRefusesAProfileWithASecondCopyOfAHashedField is the AUDIT-2 duplicate-key
// finding asserted where its consequence was demonstrated, rather than only at the
// loader.
//
// The probe that found it: append a second `"review_by"` to the profile a vend is
// about to run against. Before the fix that vend SUCCEEDED, and the birth certificate
// printed `review by 2099-12-31` while the file on disk still read 2027-06-30 on the
// line a reviewer's eye lands on. encoding/json takes the last occurrence and reports
// nothing; DisallowUnknownFields does not fire, because the key is known twice; and the
// schema's `additionalProperties: false` constrains which names may appear, not how
// often.
//
// Asserted at the command rather than only in internal/envprofile because that is where
// the value became a printed claim. A unit test on the loader would pass equally well if
// vend later read the profile some other way.
func TestVendRefusesAProfileWithASecondCopyOfAHashedField(t *testing.T) {
	g, _ := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	data, err := os.ReadFile(profile) //nolint:gosec // a path this test just created
	if err != nil {
		t.Fatalf("read the profile: %v", err)
	}
	const original = `"review_by": "2027-06-30",`
	if !strings.Contains(string(data), original) {
		t.Fatalf("test setup: no review_by to duplicate in:\n%s", data)
	}
	// Appended after the original, which is the direction that wins: the visible line
	// stays and the value automat acts on is the one below it.
	doubled := strings.Replace(string(data), original,
		original+"\n  "+`"review_by": "2099-12-31",`, 1)
	if werr := os.WriteFile(profile, []byte(doubled), 0o600); werr != nil {
		t.Fatalf("write the profile: %v", werr)
	}

	out, _, err := runCLI(t, g, vendArgs(profile)...)
	if err == nil {
		t.Fatalf("vend accepted a profile with two review_by keys.\noutput:\n%s", out)
	}
	if !strings.Contains(err.Error(), "appears twice") {
		t.Errorf("the refusal does not name the duplicate key, so an operator is pointed at the wrong "+
			"thing:\n%v", err)
	}
	// And it must not have got as far as printing the winning value as a fact.
	if strings.Contains(out, "2099-12-31") {
		t.Errorf("the output states the appended review date as though it were the profile's:\n%s", out)
	}
}

// TestVendWillNotAdoptAnAccountItWasNotAskedToVend is the same harm as the test
// above, reached through a different door — and the door nobody had to type an id
// into.
//
// vend adopts on an email match rather than creating a second account, because one
// address belongs to exactly one AWS account (DESIGN §3, fact 11) and rule 4 needs a
// re-run to be safe. Uniqueness makes the address identify one account; it does not
// make that account automat's. Any account in the search containers holding the
// address the profile resolves to was adopted: the profile's SCPs attached to it, a
// birth certificate written for it, and — sitting under the root, where a fresh
// account lands — a MoveAccount into the destination OU, which moves it out from
// under every policy attached where it was.
//
// Two cases, and the second is the point. A name mismatch refuses. An account that
// coincides on BOTH the address and the name is still adopted, because that is a
// corroboration and not a proof: the authoritative check is automat:vended-by, which
// needs a ListTagsForResource grant the vendor-role bundle does not contain
// (docs/open-questions.md Q19). A test that asserted only the refusal would let a
// reader believe the stronger claim.
func TestVendWillNotAdoptAnAccountItWasNotAskedToVend(t *testing.T) {
	// The address account.email_pattern resolves --name Genomics to.
	const vendEmail = "research-admin+Genomics@dept.example.edu"

	t.Run("a name mismatch refuses, and nothing moves", func(t *testing.T) {
		g, f := vendWorld(t)
		// Under the root, which is where an account automat did not vend most
		// plausibly sits and where the adoption also produces a move.
		victim := f.State.SeedAccount("Payroll", vendEmail, f.State.RootID)
		before := f.State.ParentOf(victim)

		_, stderr, err := runCLI(t, g, vendArgs(vendProfileJSON(t, nil))...)
		if err == nil {
			t.Fatalf("vend adopted account %s, which it was not asked to vend; it is now under %s "+
				"carrying this profile's policies", victim, f.State.ParentOf(victim))
		}
		// Both names, so the operator can tell their own typo from somebody else's
		// account — the two have entirely different remedies.
		for _, want := range []string{"Payroll", "Genomics", vendEmail} {
			if !strings.Contains(stderr, want) && !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q:\n%v\n%s", want, err, stderr)
			}
		}
		if got := f.State.ParentOf(victim); got != before {
			t.Errorf("the account moved from %s to %s despite the refusal", before, got)
		}
		if got := f.Vend.CallCount("MoveAccount"); got != 0 {
			t.Errorf("MoveAccount was called %d times on an account vend refused to adopt", got)
		}
		// And it did not fall through to a create. That path exists: AWS would answer
		// EMAIL_ALREADY_EXISTS and the operator would be told the address is in use
		// somewhere automat cannot see, while automat is looking straight at it.
		if got := f.Vend.CallCount("CreateAccount"); got != 0 {
			t.Errorf("CreateAccount was called %d times after the refusal, so the refusal is a "+
				"skip: AWS answers EMAIL_ALREADY_EXISTS and reports the wrong cause", got)
		}
	})

	t.Run("both keys coinciding is still adopted, which is the limit of this check", func(t *testing.T) {
		g, f := vendWorld(t)
		adopted := f.State.SeedAccount("Genomics", vendEmail, testVendOU)

		if _, _, err := runCLI(t, g, vendArgs(vendProfileJSON(t, nil))...); err != nil {
			t.Fatalf("vend refused an account matching on both email and name, which breaks rule 4: "+
				"the second run of an interrupted vend is exactly this state. %v", err)
		}
		if got := f.State.AccountIDs(); len(got) != 1 || got[0] != adopted {
			t.Errorf("accounts are %v, want just the adopted %s — a second account means the "+
				"idempotent re-run created one", got, adopted)
		}
	})
}

// TestVendRefusesValuesItWouldHaveToRecord is CLAUDE.md rule 8 at the CLI layer.
//
// Four flags whose values automat writes into a record a person reads back and types
// onto a command line: the name reaches the plan and the birth certificate, the email
// is the account's permanent key, the OU id is printed for an operator to type into
// --ou, and the request id is the only handle on an in-flight create. A value
// carrying a quote makes a record suggest a different command than the one it appears
// to be; a value carrying whitespace cannot be double-clicked, so it is retyped and
// retyped wrong.
//
// Refused at the boundary rather than at write time, because a value refused only at
// write time has already been sent to AWS.
func TestVendRefusesValuesItWouldHaveToRecord(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "a name carrying a quote",
			args: []string{"--name", `Genomics"; rm -rf /`},
			want: "is not an account name",
		},
		{
			name: "a name with a trailing space",
			args: []string{"--name", "Genomics "},
			// Trimmed rather than refused: a trailing space in a flag value is a
			// paste artifact, not an attack, and trimming is what an operator
			// expects. The refusal is for what survives trimming.
			want: "",
		},
		{
			name: "a name carrying a newline",
			args: []string{"--name", "Genomics\nAlsoThis"},
			want: "is not an account name",
		},
		{
			name: "an email carrying a space",
			args: []string{"--name", "Genomics", "--email", "a b@example.edu"},
			want: "is not an address",
		},
		{
			name: "an email with no domain dot",
			args: []string{"--name", "Genomics", "--email", "someone@localhost"},
			want: "is not an address",
		},
		{
			name: "an OU id that is not one",
			args: []string{"--name", "Genomics", "--ou", "Research CUI"},
			want: "is not an OU or root id",
		},
		{
			name: "a resume token carrying a metacharacter",
			args: []string{"--resume", "car-exam0001$(id)"},
			want: "is not a create-account request id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, f := vendWorld(t)
			profile := vendProfileJSON(t, nil)
			args := append([]string{"vend", "--environment-profile", profile, "--dry-run"}, tc.args...)
			_, _, err := runCLI(t, g, args...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want acceptance, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("the value was accepted; automat must refuse to record it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say %q:\n%s", tc.want, err)
			}
			if seen := vendWritesSeen(f); len(seen) > 0 {
				t.Errorf("the refusal arrived after %v; it must arrive at the boundary", seen)
			}
		})
	}
}

// TestVendSubstitutesTheEmailPattern.
//
// Nothing else in automat substitutes envprofile.EmailNamePlaceholder, so this is
// the only place `research-admin+{name}@dept.edu` becomes an address. Two sources,
// profile before config, and both refusals matter: a pattern with no placeholder
// produces the same address every time, so the second vend would be refused by AWS
// as a duplicate, and that is much better said here.
func TestVendSubstitutesTheEmailPattern(t *testing.T) {
	t.Run("from the environment profile", func(t *testing.T) {
		g, f := vendWorld(t)
		profile := vendProfileJSON(t, nil)
		if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
			t.Fatalf("vend: %v", err)
		}
		if got := len(f.State.AccountIDs()); got != 1 {
			t.Fatalf("want 1 account, got %d", got)
		}
	})

	t.Run("a name with a space becomes a hyphen", func(t *testing.T) {
		g, _ := vendWorld(t)
		profile := vendProfileJSON(t, nil)
		out, _, err := runCLI(t, g, "vend", "--environment-profile", profile,
			"--name", "Genomics Lab")
		if err != nil {
			t.Fatalf("vend: %v", err)
		}
		if !strings.Contains(out, "research-admin+Genomics-Lab@dept.example.edu") {
			t.Errorf("the birth certificate does not show the substituted address:\n%s", out)
		}
	})

	t.Run("a pattern with no placeholder is refused", func(t *testing.T) {
		g, _ := vendWorld(t)
		profile := vendProfileJSON(t, func(doc map[string]any) {
			doc["account"] = map[string]any{"email_pattern": "research-admin@dept.example.edu"}
		})
		_, _, err := runCLI(t, g, vendArgs(profile, "--dry-run")...)
		if err == nil {
			t.Fatal("a pattern with no {name} was accepted; every vend would produce the same address")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("the refusal does not explain what would go wrong:\n%s", err)
		}
	})

	t.Run("the config file supplies a pattern when the profile does not", func(t *testing.T) {
		g, f := vendWorld(t)
		writeConfig(t, g, "[context.c]\n"+
			"org = \""+testOrg+"\"\n"+
			"email_pattern = \"cloud+{name}@example.edu\"\n")
		profile := vendProfileJSON(t, func(doc map[string]any) {
			delete(doc, "account")
		})
		if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
			t.Fatalf("vend: %v", err)
		}
		if got := len(f.State.AccountIDs()); got != 1 {
			t.Fatalf("want 1 account, got %d", got)
		}
	})

	t.Run("no pattern anywhere is refused rather than invented", func(t *testing.T) {
		g, _ := vendWorld(t)
		profile := vendProfileJSON(t, func(doc map[string]any) {
			delete(doc, "account")
		})
		_, _, err := runCLI(t, g, vendArgs(profile, "--dry-run")...)
		if err == nil {
			t.Fatal("a vend with no email and no pattern was accepted")
		}
		if !strings.Contains(err.Error(), "--email") {
			t.Errorf("the refusal does not name the flag that fixes it:\n%s", err)
		}
	})
}

// TestVendRequiresAnEnvironmentProfile, and says which flag.
//
// The two-flag confusion this guards is real and DESIGN §7a names it: --profile is
// the AWS credential profile everywhere in every AWS tool, so the document flag
// cannot be called that, and an operator who tries --profile has to be told which
// one they wanted.
func TestVendRequiresAnEnvironmentProfile(t *testing.T) {
	g, _ := vendWorld(t)
	_, _, err := runCLI(t, g, "vend", "--name", "Genomics")
	if err == nil {
		t.Fatal("vend with no environment profile succeeded; there is no default posture")
	}
	if !strings.Contains(err.Error(), "--environment-profile") {
		t.Errorf("the refusal does not name the flag:\n%s", err)
	}
	if !strings.Contains(err.Error(), "credential profile") {
		t.Errorf("the refusal does not disambiguate --profile (DESIGN §7a):\n%s", err)
	}
}

// TestVendHoldsNoOrganizationCreationCapability.
//
// The narrow-interface argument is only true if it is true of the wiring, and the
// wiring is what this asserts: `vend` never builds an OrgInit client, so
// CreateOrganization and EnablePolicyType are unreachable from it no matter what the
// code does. A test that read the code could not tell the difference between
// "does not call it" and "cannot".
func TestVendHoldsNoOrganizationCreationCapability(t *testing.T) {
	g, f := vendWorld(t)
	g.newOrgInit = nil // no constructor: reaching for one would fall through to the SDK
	profile := vendProfileJSON(t, nil)

	if _, _, err := runCLI(t, g, vendArgs(profile)...); err != nil {
		t.Fatalf("vend built an org-init client, or failed for another reason: %v", err)
	}
	for _, op := range []string{"CreateOrganization", "EnablePolicyType"} {
		if got := f.Init.CallCount(op); got != 0 {
			t.Errorf("vend called %s %d times", op, got)
		}
	}
}

// TestVendRefusesAnOUPathItIsNotPermittedToCreate.
//
// create_intermediate_ous exists so that OU creation can be central IT's to do. A
// vend that created the path anyway would be overruling the document it was given,
// which is the one thing an environment profile is for.
func TestVendRefusesAnOUPathItIsNotPermittedToCreate(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, func(doc map[string]any) {
		doc["placement"] = map[string]any{
			"target_ou":               testVendOU,
			"ou_path":                 []any{"Genomics"},
			"create_intermediate_ous": false,
		}
	})

	_, _, err := runCLI(t, g, vendArgs(profile, "--dry-run")...)
	if err == nil {
		t.Fatal("a profile forbidding OU creation was vended into a path that does not exist")
	}
	if !strings.Contains(err.Error(), "create_intermediate_ous") {
		t.Errorf("the refusal does not name the field that governs it:\n%s", err)
	}
	if got := f.Vend.CallCount("CreateOrganizationalUnit"); got != 0 {
		t.Errorf("the OU was created %d times despite the profile forbidding it", got)
	}

	// With the field true, the same profile vends and the account lands in the
	// nested OU rather than in target_ou.
	g2, f2 := vendWorld(t)
	profile2 := vendProfileJSON(t, func(doc map[string]any) {
		doc["placement"] = map[string]any{
			"target_ou":               testVendOU,
			"ou_path":                 []any{"Genomics"},
			"create_intermediate_ous": true,
		}
	})
	if _, _, err := runCLI(t, g2, vendArgs(profile2)...); err != nil {
		t.Fatalf("vend with create_intermediate_ous: %v", err)
	}
	// Not ouIDByName: that looks under the root, and the whole point of ou_path is
	// that this OU is below target_ou rather than beside it.
	nested := ""
	for _, id := range f2.State.OUIDsUnder(testVendOU) {
		if f2.State.OUName(id) == "Genomics" {
			nested = id
		}
	}
	if nested == "" {
		t.Fatalf("no OU named Genomics below %s; the path was not created", testVendOU)
	}
	accounts := f2.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("want 1 account, got %v", accounts)
	}
	if got := f2.State.ParentOf(accounts[0]); got != nested {
		t.Errorf("the account is under %s, want the nested OU %s", got, nested)
	}
}

// TestVendBirthCertificateCarriesTheHashes is DESIGN §7 step 6.
//
// Account id, OU, control artifact hash, enforcement summary — and the hashes are
// what make the claim checkable rather than a label. A birth certificate naming
// cmmc-l1 without its content hash tells an auditor which document to go and read,
// but not which VERSION of it was compiled in.
func TestVendBirthCertificateCarriesTheHashes(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	out, _, err := runCLI(t, g, vendArgs(profile)...)
	if err != nil {
		t.Fatalf("vend: %v", err)
	}
	accountID := f.State.AccountIDs()[0]

	for _, want := range []string{
		"Birth certificate:",
		accountID,
		testVendOU,
		testOrg,
		"research-cui sha256:",
		"cmmc-l1 sha256:",
		"baseline-protection sha256:",
		"dfars-7012 sha256:",
		"NOT APPLIED",
		"evidence",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the birth certificate does not carry %q:\n%s", want, out)
		}
	}
	// Every control set the vend compiled, including the one the profile did not
	// name: baseline-protection is always compiled in (DESIGN §10), so a birth
	// certificate that omitted it would understate what the account is subject to.
	if strings.Count(out, "sha256:") < 4 {
		t.Errorf("the birth certificate carries fewer hashes than the vend compiled:\n%s", out)
	}
}

// loadVendManifest reads the manifest a vend wrote from the default evidence
// directory, from disk — not from memory. See TestVendManifestChainValidates for why
// the round trip is the point.
func loadVendManifest(t *testing.T, accountID string) *evidence.Manifest {
	t.Helper()
	path := filepath.Join("evidence", accountID+".json")
	raw, err := os.ReadFile(path) //nolint:gosec // a path this test just wrote in its own temp dir
	if err != nil {
		t.Fatalf("read the evidence manifest at %s: %v", path, err)
	}
	var m evidence.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("the manifest at %s is not parseable JSON: %v", path, err)
	}
	return &m
}

// assertGolden compares got against testdata/golden/<name>, updating it when
// AUTOMAT_UPDATE_GOLDEN is set. The env-var escape hatch is the same idiom the other
// golden tests in this repo use; the point of the file is that a change to it shows
// up as a reviewable diff rather than as a passing test.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(packageDir, "testdata", "golden", name)
	if os.Getenv("AUTOMAT_UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create the golden directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("update the golden file: %v", err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // a fixed path inside the package's testdata
	if err != nil {
		t.Fatalf("read the golden file %s: %v\nRe-run with AUTOMAT_UPDATE_GOLDEN=1 to create it",
			path, err)
	}
	if got != string(want) {
		t.Errorf("output does not match %s.\n--- want ---\n%s\n--- got ---\n%s\n"+
			"If the change is intended, re-run with AUTOMAT_UPDATE_GOLDEN=1 and review the diff",
			path, want, got)
	}
}
