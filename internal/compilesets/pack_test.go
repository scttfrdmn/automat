// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Tests for the packer: the quota arithmetic, the rendering, and the conflict
// reports.
//
// The packer's failures all land in the same place operationally — CreatePolicy or
// AttachPolicy rejects the document mid-vend, after the account exists, which is
// the parked state DESIGN §4 describes. So every test here is about catching a
// problem before the API call rather than about output aesthetics.

const testAutomationRole = "arn:aws:iam::333333333333:role/automat-automation"

func packOpts() PackOptions {
	return PackOptions{NamePrefix: "automat-test", AutomationRoleARN: testAutomationRole}
}

// testGlobalNamespaces is the global-service exemption list the tests use.
//
// A FIXTURE, not the list automat ships. The real one is artifact-level catalog
// data supplied by baseline-protection (see catalogs/baseline-protection.json),
// which is the whole point: a list compiled into this package would be a control
// whose scope nobody can review. It is repeated here because the packer's tests
// are about the shape of the rendered policy, and a test that read the shipped
// catalog would fail for reasons about the catalog rather than about the packer.
//
// TestTheShippedCatalogSuppliesTheNamespacesThatWouldBrickAnAccount is what holds
// the real list to the same standard.
var testGlobalNamespaces = []string{
	"access-analyzer", "account", "acm", "aws-marketplace", "aws-portal",
	"budgets", "ce", "cloudfront", "config", "cur", "directconnect",
	"globalaccelerator", "health", "iam", "kms", "networkmanager",
	"organizations", "pricing", "route53", "route53domains", "shield", "sts",
	"support", "trustedadvisor", "waf", "wellarchitected",
}

// withGlobalExemptions supplies the exemption list a Merged needs before either
// allowlist can be rendered.
//
// A helper because most tests here are about statement semantics rather than
// about where the list came from, and because forgetting it produces the
// missing-list PackError, which would fail the test for the wrong reason.
// TestAConstrainedSetWithNoExemptionListIsRefused is the test that is about the
// omission.
func withGlobalExemptions(m *Merged) *Merged {
	m.RegionDenyExemptServices = newAllowSet(testGlobalNamespaces, "set:fixture")
	return m
}

// mustPack packs and fails the test on error.
func mustPack(t *testing.T, m *Merged, opts PackOptions) *Packed {
	t.Helper()
	got, err := Pack(m, opts)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return got
}

// packError packs, requires a *PackError, and returns it.
//
// It requires the typed error rather than any error, because CLAUDE.md rule 7
// makes the remediation text part of the contract: a bare fmt.Errorf here would
// leave an operator with "cannot pack" and nothing to do about it.
func packError(t *testing.T, m *Merged, opts PackOptions) *PackError {
	t.Helper()
	got, err := Pack(m, opts)
	if err == nil {
		t.Fatalf("expected a pack error, got %d policies", len(got.Policies))
	}
	var pe *PackError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a *PackError with remediation text, got %T: %v", err, err)
	}
	if pe.Remediation == "" {
		t.Errorf("the error has no remediation text, so it tells the operator what failed but not what "+
			"to do about it (CLAUDE.md rule 7): %v", pe)
	}
	return pe
}

func TestPackRendersAValidPolicyDocument(t *testing.T) {
	m := &Merged{Statements: []Statement{
		deny("ProtectRecorder", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil,
			exempt(artifact.AutomationRolePlaceholder, "automat configures the recorder")),
	}}

	got := mustPack(t, m, packOpts())
	if len(got.Policies) != 1 {
		t.Fatalf("expected one policy, got %d", len(got.Policies))
	}
	p := got.Policies[0]
	if p.Name != "automat-test-1" {
		t.Errorf("policy name %q does not follow the prefix-index convention", p.Name)
	}

	var doc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string   `json:"Sid"`
			Effect    string   `json:"Effect"`
			Action    []string `json:"Action"`
			NotAction []string `json:"NotAction"`
			Resource  []string `json:"Resource"`
			Condition map[string]map[string][]string
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(p.Document), &doc); err != nil {
		t.Fatalf("the packed document is not valid JSON: %v\n%s", err, p.Document)
	}
	if doc.Version != "2012-10-17" {
		t.Errorf("policy version is %q; IAM requires 2012-10-17", doc.Version)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected one statement, got %d", len(doc.Statement))
	}
	st := doc.Statement[0]
	if st.Effect != "Deny" {
		t.Errorf("effect is %q; an SCP Allow does not compose under union (DESIGN §9)", st.Effect)
	}

	// The exemption became a condition, and the placeholder was materialized.
	arns := st.Condition["ArnNotLike"]["aws:PrincipalArn"]
	if len(arns) != 1 || arns[0] != testAutomationRole {
		t.Fatalf("expected the automation role ARN in the ArnNotLike condition, got %v", arns)
	}
	if strings.Contains(p.Document, artifact.AutomationRolePlaceholder) {
		t.Errorf("the rendered policy still contains the placeholder %q; IAM would treat it as a literal "+
			"ARN matching no principal, so the exemption would silently not exist",
			artifact.AutomationRolePlaceholder)
	}
}

// TestTheExemptionOperatorIsArnNotLike.
//
// aws:PrincipalArn is an ARN-typed key. The ARN operators normalize case and
// partition; the string operators compare literally, so a role name whose case
// differs from the catalog's spelling would silently fail to match under
// StringNotLike and the exemption would not exist. The failure is invisible: the
// policy is valid, the condition is present, and the principal is denied anyway.
func TestTheExemptionOperatorIsArnNotLike(t *testing.T) {
	m := &Merged{Statements: []Statement{
		deny("ProtectRecorder", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil,
			exempt(breakGlass, "incident response")),
	}}
	doc := mustPack(t, m, packOpts()).Policies[0].Document

	if !strings.Contains(doc, `"ArnNotLike"`) {
		t.Errorf("the exemption condition does not use ArnNotLike:\n%s", doc)
	}
	for _, wrong := range []string{"StringNotLike", "StringNotEquals\":{\"aws:PrincipalArn"} {
		if strings.Contains(doc, wrong) {
			t.Errorf("the exemption condition uses %s on an ARN-typed key; case and partition "+
				"normalization would not apply and a mismatched spelling would silently drop the "+
				"exemption:\n%s", wrong, doc)
		}
	}
}

// TestAnUnresolvedPlaceholderIsRefused.
//
// The packer must not render artifact.AutomationRolePlaceholder literally. IAM
// would accept the policy — it is a syntactically fine string — and the condition
// would match no principal, so the exemption would silently not exist and
// automat's own baseline work would be denied by the control it just installed.
func TestAnUnresolvedPlaceholderIsRefused(t *testing.T) {
	m := &Merged{Statements: []Statement{
		deny("ProtectRecorder", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil,
			exempt(artifact.AutomationRolePlaceholder, "automat configures the recorder")),
	}}

	pe := packError(t, m, PackOptions{NamePrefix: "automat-test"})
	if !strings.Contains(pe.Reason, artifact.AutomationRolePlaceholder) {
		t.Errorf("the error does not name the placeholder it could not resolve: %v", pe)
	}
	if len(pe.Sources) == 0 {
		t.Error("the error does not name the control set the statement came from, so an operator cannot " +
			"find the exemption to fix")
	}
}

// TestAnExistingArnNotLikeOnPrincipalArnIsAConflict.
//
// If a catalog already constrains aws:PrincipalArn under ArnNotLike, adding the
// exemption ARNs to that list would LOOSEN the catalog's own condition — the Deny
// would stop applying to principals the catalog meant it to cover. Overriding it
// silently is the widening DESIGN §9 forbids, so it is an error naming both halves.
func TestAnExistingArnNotLikeOnPrincipalArnIsAConflict(t *testing.T) {
	m := &Merged{Statements: []Statement{
		deny("ProtectRecorder", []string{"config:StopConfigurationRecorder"}, []string{"*"},
			artifact.Condition{"ArnNotLike": {"aws:PrincipalArn": {centralIT}}},
			exempt(breakGlass, "incident response")),
	}}

	pe := packError(t, m, packOpts())
	for _, want := range []string{"ArnNotLike", "aws:PrincipalArn", centralIT} {
		if !strings.Contains(pe.Error(), want) {
			t.Errorf("the conflict report does not mention %q, so the operator cannot see which two "+
				"constraints collided: %v", want, pe)
		}
	}
}

// TestAStatementWithNoActionsIsRefused.
//
// A Deny naming no actions denies nothing. It is a catalog bug, and the packer is
// the last place it can be caught with a message that names the control — after
// this the policy attaches, enforces nothing, and `verify` reports the control as
// covered.
func TestAStatementWithNoActionsIsRefused(t *testing.T) {
	m := &Merged{Statements: []Statement{{
		SCPStatement: artifact.SCPStatement{Sid: "Empty", Effect: "Deny", Resource: []string{"*"}},
		Origins:      []string{"set:empty"},
	}}}
	pe := packError(t, m, packOpts())
	if !strings.Contains(pe.Reason, "denies nothing") {
		t.Errorf("the error should say the statement denies nothing: %v", pe)
	}
}

func TestPackOfAnEmptyControlSetIsNotAnError(t *testing.T) {
	// A control set may be entirely detective. Returning an empty pack rather than
	// an error means the vend path needs no special case and `verify` reports the
	// enforcement-class count honestly.
	got := mustPack(t, &Merged{}, packOpts())
	if len(got.Policies) != 0 {
		t.Fatalf("expected no policies, got %d", len(got.Policies))
	}
	if len(got.Warnings) != 0 {
		t.Errorf("an empty pack should warn about nothing, got %v", got.Warnings)
	}
}

// TestTheErrorMessageCarriesReasonRemediationAndSources.
//
// The Sources field is only useful if it reaches the operator, and Error() is the
// only path the CLI prints. A jam that replaced the rendered source list with a
// placeholder passed every other test in this file, because they all read the
// struct field directly — so this asserts the rendering, not the data.
func TestTheErrorMessageCarriesReasonRemediationAndSources(t *testing.T) {
	e := &PackError{
		Reason:      "the reason it failed",
		Remediation: "what to do instead",
		Sources:     []string{"set-a:control-1", "set-b:control-2"},
	}
	msg := e.Error()
	for _, want := range []string{"the reason it failed", "what to do instead", "set-a:control-1", "set-b:control-2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the rendered error omits %q, so the operator never sees it: %s", want, msg)
		}
	}
}

// TestALongSourceListIsTruncatedInTheMessageButNotInTheField.
//
// The slot-overflow error's source list is every control in every compiled set —
// hundreds of entries for a real union. An error whose remediation text has scrolled
// off the top of the terminal has the same effect as no remediation text, which is
// the failure CLAUDE.md rule 7 exists to prevent. So the MESSAGE truncates and says
// how many it dropped; the FIELD does not, because a caller rendering a structured
// conflict report wants all of them.
func TestALongSourceListIsTruncatedInTheMessageButNotInTheField(t *testing.T) {
	var sources []string
	for i := 0; i < maxSourcesShown*4; i++ {
		sources = append(sources, fmt.Sprintf("set:control-%03d", i))
	}
	e := &PackError{Reason: "r", Remediation: "m", Sources: sources}

	msg := e.Error()
	if !strings.Contains(msg, fmt.Sprintf("and %d more", len(sources)-maxSourcesShown)) {
		t.Errorf("the message does not say how many sources it dropped, so a truncated list reads as a "+
			"complete one: %s", msg)
	}
	if strings.Contains(msg, sources[len(sources)-1]) {
		t.Errorf("the message was not truncated: %s", msg)
	}
	if !strings.Contains(msg, "m") || !strings.Contains(msg, "r") {
		t.Errorf("truncation dropped the reason or the remediation: %s", msg)
	}
	if len(e.Sources) != len(sources) {
		t.Errorf("Error() mutated Sources from %d entries to %d; the field is the structured report and "+
			"must stay complete", len(sources), len(e.Sources))
	}
}

func TestPackRequiresANamePrefix(t *testing.T) {
	m := &Merged{Statements: []Statement{deny("A", []string{"iam:CreateUser"}, []string{"*"}, nil)}}
	pe := packError(t, m, PackOptions{})
	if !strings.Contains(pe.Remediation, "report it") {
		t.Errorf("a missing prefix is automat's bug, not the operator's, and the remediation should say "+
			"so: %v", pe)
	}
}

// TestEverySidInAPolicyIsUnique.
//
// IAM requires it and rejects the whole document with MalformedPolicyDocument
// otherwise — at CreatePolicy, mid-vend, with the account already created.
//
// This is a regression test. The merge originally gave every bucket in a guard
// group the Sid of whichever statement seeded the group, and since a guard is
// effect + resource + condition, every unconditional Deny on "*" lands in one
// group. Two frameworks' worth of unconditional Denies therefore produced several
// statements sharing one Sid, and nothing in the property suite noticed: the merge
// was semantically right, and Denies does not read the Sid. A golden file caught
// it, which is the argument for having them.
func TestEverySidInAPolicyIsUnique(t *testing.T) {
	for _, sc := range goldenScenarios {
		t.Run(sc.dir, func(t *testing.T) {
			for _, p := range mustPack(t, sc.build(t), packOpts()).Policies {
				var doc struct {
					Statement []struct{ Sid string } `json:"Statement"`
				}
				if err := json.Unmarshal([]byte(p.Document), &doc); err != nil {
					t.Fatal(err)
				}
				seen := map[string]bool{}
				for _, st := range doc.Statement {
					if st.Sid == "" {
						t.Errorf("%s has a statement with no Sid", p.Name)
					}
					if seen[st.Sid] {
						t.Errorf("%s uses the Sid %q twice; IAM rejects the whole document as malformed, "+
							"so this vend fails at CreatePolicy with the account already created",
							p.Name, st.Sid)
					}
					seen[st.Sid] = true
				}
			}
		})
	}
}

// TestASidIsAlphanumericAndStable.
//
// Alphanumeric because IAM allows nothing else — the same rule
// artifact.Validate enforces on catalog Sids. Stable because a Sid that changed
// between two packs of the same input would make the ensure step rewrite a policy
// nothing asked it to change, and every rewrite is an audit event and a chance to
// fail partway.
func TestASidIsAlphanumericAndStable(t *testing.T) {
	first := mustPack(t, goldenMerged(t), packOpts())
	second := mustPack(t, goldenMerged(t), packOpts())

	// The same pattern artifact.Validate holds catalog Sids to, spelled out rather
	// than imported: a derived Sid and a hand-written one have to satisfy the same
	// IAM rule, and sharing the variable would let a loosened validator quietly
	// loosen this.
	alnum := regexp.MustCompile(`^[A-Za-z0-9]+$`)

	for i, p := range first.Policies {
		for j, st := range p.Statements {
			if !alnum.MatchString(st.Sid) {
				t.Errorf("Sid %q is not alphanumeric; IAM allows only letters and digits", st.Sid)
			}
			if got := second.Policies[i].Statements[j].Sid; got != st.Sid {
				t.Errorf("the same input produced Sid %q then %q", st.Sid, got)
			}
		}
	}
}

// TestASidDoesNotClaimToDescribeTheStatement.
//
// The other half of the Sid bug, and the half that survives uniqueness. Before the
// fix a statement denying iam:CreateUser was labeled ProtectCloudTrail, because a
// CloudTrail statement happened to seed its guard group. The Sid is the only
// human-readable handle in a rendered policy — what an auditor reads to find a
// control and what an operator greps when a Deny blocks something — and a
// confidently wrong label is worse than an opaque one, because it stops the reader
// looking.
//
// So the invariant is negative: a merged Sid must not be inherited from any input
// statement, because an inherited name is a name that can be wrong. Opaque and
// derived is the trade.
func TestASidDoesNotClaimToDescribeTheStatement(t *testing.T) {
	inputs := []string{
		"ProtectConfigRecorder", "ProtectCloudTrail", "DenyRootUser",
		"AuditLogProtection", "DenyIAMUserCreation",
	}
	for _, p := range mustPack(t, Merge(goldenFrameworkA(t), goldenFrameworkB(t)), packOpts()).Policies {
		for _, st := range p.Statements {
			for _, in := range inputs {
				if st.Sid == in {
					t.Errorf("merged statement over %v carries the input Sid %q; a merged statement covers "+
						"actions from several inputs, so any inherited name describes at most one of them",
						st.Action, in)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Quotas
// ---------------------------------------------------------------------------

// TestTheQuotaArithmeticMatchesAWS pins the numbers themselves.
//
// These are DESIGN §16's load-bearing AWS facts, and CLAUDE.md rule 2 makes them
// constraints rather than suggestions. A test that reads them from the constants it
// is testing would be a tautology, so the values are written out here: changing
// either one has to be a deliberate edit in two places, with a DESIGN amendment to
// justify it.
func TestTheQuotaArithmeticMatchesAWS(t *testing.T) {
	if MaxPolicySize != 5120 {
		t.Errorf("MaxPolicySize is %d; AWS's SCP size limit is 5120 characters (DESIGN §16)", MaxPolicySize)
	}
	if MaxPoliciesPerTarget != 5 {
		t.Errorf("MaxPoliciesPerTarget is %d; AWS attaches at most 5 SCPs to one target (DESIGN §16)",
			MaxPoliciesPerTarget)
	}
	if ReservedPolicySlots != 2 {
		t.Errorf("ReservedPolicySlots is %d; one slot is central IT's institutional SCP and one is "+
			"FullAWSAccess, whose removal denies everything", ReservedPolicySlots)
	}
	if AvailablePolicySlots != 3 {
		t.Errorf("AvailablePolicySlots is %d, want 3", AvailablePolicySlots)
	}
	if UsablePolicySize >= MaxPolicySize {
		t.Errorf("UsablePolicySize (%d) must be under MaxPolicySize (%d): the automation role ARN "+
			"substituted for the placeholder is longer than the placeholder, and a packer that fills to "+
			"exactly the limit fails at attach time with an account already created",
			UsablePolicySize, MaxPolicySize)
	}
}

// TestNoPackedPolicyExceedsTheSizeLimit, swept across every fixture size that
// packs at all.
//
// Swept rather than sampled because the interesting sizes are the ones just over a
// bin boundary, and which n those are is a property of the renderer. One sampled
// size tests one boundary by luck.
func TestNoPackedPolicyExceedsTheSizeLimit(t *testing.T) {
	var packed, multi int
	for n := 1; n <= 120; n++ {
		got, err := Pack(wideMerged(t, n), packOpts())
		if err != nil {
			continue
		}
		packed++
		if len(got.Policies) > 1 {
			multi++
		}
		for _, p := range got.Policies {
			if len(p.Document) > MaxPolicySize {
				t.Errorf("with %d statements, policy %s is %d characters, over AWS's %d-character limit",
					n, p.Name, len(p.Document), MaxPolicySize)
			}
		}
	}
	t.Logf("swept %d fixture sizes that packed, %d of them into more than one policy", packed, multi)
	if multi == 0 {
		t.Error("no fixture size needed more than one policy, so the sweep never exercised bin packing")
	}
}

// TestOverflowingTheAvailableSlotsIsAnErrorNamingTheWayOut.
//
// The important half is the remediation. An operator who has compiled too many
// control sets for one target has two outs — fewer sets, or attach at a parent OU
// so the statements are inherited — and inheritance not consuming a target's slots
// is the non-obvious one. Without it the message is "does not fit", which reads as
// "automat cannot do this".
func TestOverflowingTheAvailableSlotsIsAnErrorNamingTheWayOut(t *testing.T) {
	pe := packError(t, wideMerged(t, 400), packOpts())

	if !strings.Contains(pe.Reason, fmt.Sprintf("%d of", AvailablePolicySlots)) &&
		!strings.Contains(pe.Reason, fmt.Sprintf("but only %d", AvailablePolicySlots)) {
		t.Errorf("the error does not say how many slots were available: %v", pe)
	}
	for _, want := range []string{"parent OU", "inherit"} {
		if !strings.Contains(pe.Remediation, want) {
			t.Errorf("the remediation does not mention %q, which is the non-obvious way out: %v", want, pe)
		}
	}
	if !strings.Contains(pe.Reason, "reserved") {
		t.Errorf("the error does not explain why 2 of the 5 slots are unavailable, so the operator will "+
			"count 5 attachable policies and conclude automat is wrong: %v", pe)
	}
}

// ---------------------------------------------------------------------------
// Oversize statements: splitting the ones that can be split, refusing the rest
// ---------------------------------------------------------------------------

// hugeActions is an action list long enough that no single policy can hold the
// statement carrying it.
func hugeActions(n int) []string {
	actions := make([]string, 0, n)
	for i := 0; i < n; i++ {
		actions = append(actions, fmt.Sprintf("service%03d:LongActionNameForPadding", i))
	}
	return actions
}

// TestAnOversizeDenyIsSplitByActionRatherThanRefused.
//
// This test used to assert the opposite — that an oversize statement is its own
// error, with remediation telling the catalog author to split it. Re-measuring the
// quota numbers against the real baseline-protection set showed that advice cannot
// be followed: the merge groups actions by exemption set, so a catalog that HAS
// split its actions across seven controls sharing one exemption gets them joined
// back into one statement. The operator would have been sent to undo something they
// did not do.
//
// So the packer splits it instead, and the invariant that matters is not the shape
// of the output but that the split denies exactly what the unsplit statement did.
func TestAnOversizeDenyIsSplitByActionRatherThanRefused(t *testing.T) {
	actions := hugeActions(150)
	st := deny("Huge", actions, []string{"*"}, nil)
	m := &Merged{Statements: []Statement{st}}

	got := mustPack(t, m, packOpts())
	var packedStatements []Statement
	for _, p := range got.Policies {
		packedStatements = append(packedStatements, p.Statements...)
	}
	if len(packedStatements) < 2 {
		t.Fatalf("a %d-action statement no policy can hold produced %d packed statements; it should have "+
			"been split", len(actions), len(packedStatements))
	}

	// Behavioral equivalence, in both directions, over every action the statement
	// named and one it did not. Asserted through Denies rather than by comparing
	// action lists, because "the parts' actions union to the original" is the
	// property the *implementation* has, and what has to hold is the one an account
	// experiences.
	for _, action := range append(actions, "service999:NotDeniedAtAll") {
		req := Request{Principal: "arn:aws:iam::333333333333:role/researcher", Action: action, Resource: "*"}
		if want, have := Denies([]Statement{st}, req), Denies(packedStatements, req); want != have {
			t.Fatalf("splitting changed what the control denies: the unsplit statement denies %s = %v, "+
				"the split parts = %v", action, want, have)
		}
	}
}

// TestTheSplitPartsOfAStatementHaveDistinctSids.
//
// Nothing in the behavioral check above reads a Sid, and the parts of a split are
// the statements most likely to collide: they are copies of one statement differing
// in one field. Two identical Sids in one document is MalformedPolicyDocument at
// CreatePolicy, mid-vend, with the account already created.
func TestTheSplitPartsOfAStatementHaveDistinctSids(t *testing.T) {
	m := &Merged{Statements: []Statement{deny("Huge", hugeActions(150), []string{"*"}, nil)}}

	seen := map[string]string{}
	for _, p := range mustPack(t, m, packOpts()).Policies {
		for _, st := range p.Statements {
			if where, dup := seen[st.Sid]; dup {
				t.Errorf("split parts in %s and %s share the Sid %q", where, p.Name, st.Sid)
			}
			seen[st.Sid] = p.Name
			if st.Sid == "Huge" {
				t.Errorf("a split part kept the original Sid %q; the parts are different statements and "+
					"IAM requires the Sid to be unique within a document", st.Sid)
			}
		}
	}
}

// TestAnOversizeAllowlistIsRefusedRatherThanSplit.
//
// The one statement shape splitting must NOT be applied to. An allowlist's
// NotAction list is a conjunction — it denies everything it does not name — so two
// statements over halves of the list deny everything outside the first half OR
// outside the second, which is everything in the account. Splitting here would
// produce exactly the deny-all the NotAction discipline exists to prevent, from
// input that is merely long.
func TestAnOversizeAllowlistIsRefusedRatherThanSplit(t *testing.T) {
	services := make([]string, 0, 400)
	for i := 0; i < 400; i++ {
		services = append(services, fmt.Sprintf("averylongservicenamespace%03d", i))
	}
	m := withGlobalExemptions(&Merged{ServiceAllowlist: newAllowSet(services, "set:services")})

	pe := packError(t, m, packOpts())
	if !strings.Contains(pe.Reason, "allowlist") {
		t.Errorf("the error does not say an allowlist is the problem: %v", pe)
	}
	if !strings.Contains(pe.Reason, "service") {
		t.Errorf("the error does not name WHICH allowlist; both are the packer's own statements, so an "+
			"operator reading 'shorten the allowlist' cannot tell which of their two lists to shorten: %v", pe)
	}
	for _, want := range []string{"shorten", "cannot be split"} {
		if !strings.Contains(pe.Remediation, want) {
			t.Errorf("the remediation should say %q — an operator who has just watched the packer split a "+
				"Deny will otherwise assume this one can be split too: %v", want, pe)
		}
	}

	// The refusal has to be the only outcome: if any pack of this input succeeded,
	// the account it produced would deny every call.
	if got, err := Pack(m, packOpts()); err == nil {
		t.Fatalf("Pack accepted an unrenderable allowlist and produced %d policies", len(got.Policies))
	}
}

// TestASingleActionStatementTooLargeToRenderIsItsOwnError.
//
// The floor of the recursion. A statement denying one action cannot be halved, so
// what is oversize is its condition, resource list, or exemption list — and the
// remediation has to name those instead of "split it", which is now what the packer
// does automatically and therefore cannot be advice.
func TestASingleActionStatementTooLargeToRenderIsItsOwnError(t *testing.T) {
	var exemptions []artifact.ExemptPrincipal
	for i := 0; i < 200; i++ {
		exemptions = append(exemptions, exempt(
			fmt.Sprintf("arn:aws:iam::33333333333%d:role/a-role-with-a-long-name-%03d", i%10, i),
			fmt.Sprintf("reason %03d, stated at some length so the rendered exemption list is large", i)))
	}
	m := &Merged{Statements: []Statement{
		deny("OneAction", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil, exemptions...),
	}}

	pe := packError(t, m, packOpts())
	if !strings.Contains(pe.Reason, "single action") {
		t.Errorf("the error should say the statement is down to one action and cannot be split further: %v", pe)
	}
	if !strings.Contains(pe.Reason, "config:StopConfigurationRecorder") {
		t.Errorf("the error does not name the action, which is the only handle the operator has on which "+
			"control in the catalog to go and look at: %v", pe)
	}
	for _, want := range []string{"condition", "resource", "exemption"} {
		if !strings.Contains(pe.Remediation, want) {
			t.Errorf("the remediation should name %q as something to narrow: %v", want, pe)
		}
	}
}

// TestSplittingIsOnlyDoneWhenNeeded.
//
// The converse, and the one that keeps the golden files meaningful. renderFitting
// sits on the path of every statement the packer renders, so a size comparison
// pointed the wrong way would split statements that fit — changing every Sid, every
// document, and every ensure decision at vend time, while every behavioral test
// still passed.
func TestSplittingIsOnlyDoneWhenNeeded(t *testing.T) {
	actions := []string{"config:DeleteConfigurationRecorder", "config:StopConfigurationRecorder"}
	m := &Merged{Statements: []Statement{deny("Small", actions, []string{"*"}, nil)}}

	got := mustPack(t, m, packOpts())
	if len(got.Policies) != 1 {
		t.Fatalf("a two-action statement produced %d policies", len(got.Policies))
	}
	if n := len(got.Policies[0].Statements); n != 1 {
		t.Fatalf("a two-action statement that fits was split into %d statements", n)
	}
	if sid := got.Policies[0].Statements[0].Sid; sid != "Small" {
		t.Errorf("a statement that fits had its Sid rewritten from %q to %q; the catalog's own Sid is what "+
			"an auditor greps for", "Small", sid)
	}
}

// TestQuotaWarningsFireBeforeTheFailure.
//
// The warning matters more than the error. The operator who needs it is the one
// adding a third control set to a configuration that currently works: they hear it
// on the vend that succeeds, which is the only vend where reorganizing an OU is
// cheap. After the failure they are holding a parked account.
//
// The fixture sizes are SEARCHED for rather than written down. Hard-coding them
// once meant every change to the renderer's output — the derived Sid was one, and
// it moved every threshold — silently turned these into tests of a different case
// than the one named. Searching costs a few milliseconds and makes the subject of
// each case the property, not a number.
func TestQuotaWarningsFireBeforeTheFailure(t *testing.T) {
	t.Run("all slots consumed", func(t *testing.T) {
		got := packWhere(t, "fills every available policy slot", func(p *Packed) bool {
			return len(p.Policies) == AvailablePolicySlots
		})
		if !warns(got.Warnings, "uses all") {
			t.Errorf("a pack consuming every available slot must warn: %v", got.Warnings)
		}
		if !warns(got.Warnings, "parent OU") {
			t.Errorf("the warning should name the way out, the same one the overflow error names: %v",
				got.Warnings)
		}
	})

	t.Run("a policy over 80% of the size limit", func(t *testing.T) {
		got := packWhere(t, "produces one policy over 80% of the size limit", func(p *Packed) bool {
			return len(p.Policies) == 1 && len(p.Policies[0].Document)*100/MaxPolicySize >= 80
		})
		if !warns(got.Warnings, "characters AWS allows") {
			t.Errorf("expected a size warning, got %v", got.Warnings)
		}
	})

	t.Run("a comfortable pack warns about nothing", func(t *testing.T) {
		// The other half: a warning that always fires is not a warning. Without
		// this, a threshold bug that warns on every pack passes both cases above.
		got := packWhere(t, "produces one policy under 70% of the size limit", func(p *Packed) bool {
			return len(p.Policies) == 1 && len(p.Policies[0].Document)*100/MaxPolicySize < 70
		})
		if len(got.Warnings) != 0 {
			t.Errorf("a pack using one policy at %d%% of the size limit warned anyway, so the warnings "+
				"carry no information: %v",
				len(got.Policies[0].Document)*100/MaxPolicySize, got.Warnings)
		}
	})
}

// packWhere finds the smallest wideMerged fixture whose pack satisfies want.
//
// Failing rather than skipping when nothing matches: a quota test that quietly
// stops exercising quotas is worse than one that is red.
func packWhere(t *testing.T, describe string, want func(*Packed) bool) *Packed {
	t.Helper()
	for n := 1; n <= 200; n++ {
		got, err := Pack(wideMerged(t, n), packOpts())
		if err != nil {
			continue // past the point where any pack fits; keep looking anyway
		}
		if want(got) {
			t.Logf("fixture of %d statements %s: %d policies", n, describe, len(got.Policies))
			return got
		}
	}
	t.Fatalf("no fixture between 1 and 200 statements %s, so this case tests nothing; the packer's "+
		"size arithmetic has changed shape, not just its constants", describe)
	return nil
}

func warns(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Allowlists
// ---------------------------------------------------------------------------

// TestTheRegionAllowlistExemptsGlobalServices.
//
// A region-restriction SCP that does not exempt the global services bricks the
// account: global endpoints report as us-east-1, so a Deny on everything outside
// the allowlist denies every IAM, Organizations, and STS call — including the ones
// automat makes to build the baseline and the ones the operator would need to undo
// it.
func TestTheRegionAllowlistExemptsGlobalServices(t *testing.T) {
	m := withGlobalExemptions(&Merged{RegionAllowlist: newAllowSet([]string{"us-west-2"}, "set:regions")})
	got := mustPack(t, m, packOpts())
	if len(got.Policies) != 1 {
		t.Fatalf("expected one policy, got %d", len(got.Policies))
	}

	// Behaviorally: an IAM call from a denied region must survive.
	sts := got.Policies[0].Statements
	for _, action := range []string{"iam:CreateRole", "organizations:DescribeAccount", "sts:AssumeRole"} {
		req := Request{
			Principal: breakGlass,
			Action:    action,
			Resource:  "*",
			Region:    "eu-central-1", // outside the allowlist
		}
		if Denies(sts, req) {
			t.Errorf("the region restriction denies %s, which is a global service reached through a "+
				"us-east-1 endpoint; this policy would brick the account", action)
		}
	}
	// And a regional call from a denied region must be denied, or the control does
	// nothing.
	if !Denies(sts, Request{Principal: breakGlass, Action: "ec2:RunInstances", Resource: "*", Region: "eu-central-1"}) {
		t.Error("the region restriction does not deny ec2:RunInstances outside the allowlist, so it " +
			"enforces nothing")
	}
	if Denies(sts, Request{Principal: breakGlass, Action: "ec2:RunInstances", Resource: "*", Region: "us-west-2"}) {
		t.Error("the region restriction denies ec2:RunInstances INSIDE the allowlist")
	}
}

// TestTheShippedCatalogSuppliesTheNamespacesThatWouldBrickAnAccount.
//
// The exemption list is catalog DATA now, not a var in this package, which is what
// makes its scope reviewable — but "reviewable" is only worth something if someone
// reviews it, and the failure mode of a trimmed list is a bricked account rather
// than a failed test. So this reads the SHIPPED baseline-protection catalog, which
// is what every vend actually attaches, and asserts the namespaces whose absence
// removes the operator's own ability to recover.
//
// Reading the real catalog rather than the fixture is the entire point of the test:
// a future edit to catalogs/baseline-protection.json that drops `iam` has to break
// this rather than a production vend.
func TestTheShippedCatalogSuppliesTheNamespacesThatWouldBrickAnAccount(t *testing.T) {
	a, err := artifact.Load("../../catalogs/baseline-protection.json", artifact.LoadOptions{})
	if err != nil {
		t.Fatalf("load the shipped baseline-protection catalog: %v", err)
	}
	if len(a.RegionDenyExemptServices) == 0 {
		t.Fatal("the shipped baseline-protection catalog supplies no region_deny_exempt_services. " +
			"It is the control set attached with every vend, so nothing else will supply the list, and " +
			"the packer now refuses to render a region or service restriction without one — which is " +
			"better than the alternative, but this catalog is what makes the ordinary case work")
	}
	for _, ns := range []string{"iam", "organizations", "sts", "kms", "route53", "cloudfront", "support"} {
		if !contains(a.RegionDenyExemptServices, ns) {
			t.Errorf("%q is missing from the shipped catalog's region_deny_exempt_services; a region "+
				"restriction that covers it denies calls made through a us-east-1 global endpoint — "+
				"for iam, sts, and organizations that includes the calls an operator would make to "+
				"undo the restriction", ns)
		}
	}
}

// TestTheServiceAllowlistPermitsTheAllowlistedServices.
func TestTheServiceAllowlistPermitsTheAllowlistedServices(t *testing.T) {
	m := withGlobalExemptions(&Merged{ServiceAllowlist: newAllowSet([]string{"s3", "ec2"}, "set:services")})
	sts := mustPack(t, m, packOpts()).Policies[0].Statements

	for _, action := range []string{"s3:GetObject", "ec2:RunInstances", "iam:CreateRole"} {
		if Denies(sts, Request{Principal: breakGlass, Action: action, Resource: "*", Region: "us-east-1"}) {
			t.Errorf("the service allowlist denies %s, which is allowlisted or global", action)
		}
	}
	if !Denies(sts, Request{Principal: breakGlass, Action: "sagemaker:CreateDomain", Resource: "*", Region: "us-east-1"}) {
		t.Error("the service allowlist does not deny a service outside it, so it enforces nothing")
	}
}

// TestBothAllowlistsInOnePolicyDoNotComposeIntoADenyAll.
//
// AUDIT-0's H3 is the reason artifact.SCPStatement has no NotAction field: a Deny
// over NotAction denies everything it does not name, so two of them intersect to a
// deny-all — the first denies everything outside set A, the second everything
// outside set B, and together they deny everything outside A ∩ B, which is empty
// when the two lists are disjoint.
//
// The packer emits exactly two, and the golden files show them landing in the same
// document, so the argument that "the packer owns the shape" needs a test and not a
// paragraph. What saves it is that both statements carry the global-service
// exemption list, so A ∩ B always contains it.
//
// That is now a property of the SHAPE rather than of two lists that happen to
// agree: renderable resolves the exemption list once and hands the same slice to
// both statements, and refuses outright when no control set supplies one. The
// earlier version of this comment noted the invariant was "one trim away from
// being false" because each statement built its own list from a package var — that
// is what moving the list to catalog data and resolving it once fixed.
func TestBothAllowlistsInOnePolicyDoNotComposeIntoADenyAll(t *testing.T) {
	m := withGlobalExemptions(&Merged{
		RegionAllowlist:  newAllowSet([]string{"us-west-2"}, "set:regions"),
		ServiceAllowlist: newAllowSet([]string{"s3", "batch"}, "set:services"),
	})
	got := mustPack(t, m, packOpts())
	if len(got.Policies) != 1 {
		t.Fatalf("expected both allowlists in one policy, got %d policies", len(got.Policies))
	}
	sts := got.Policies[0].Statements

	// Something must survive, in the allowlisted region and the allowlisted
	// service. If nothing does, the account is bricked and no operator can undo it.
	permitted := []Request{
		{Principal: breakGlass, Action: "s3:GetObject", Resource: "*", Region: "us-west-2"},
		{Principal: breakGlass, Action: "batch:SubmitJob", Resource: "*", Region: "us-west-2"},
		// A global service from anywhere: the recovery path.
		{Principal: breakGlass, Action: "iam:CreateRole", Resource: "*", Region: "eu-west-1"},
		{Principal: breakGlass, Action: "organizations:ListAccounts", Resource: "*", Region: "eu-west-1"},
	}
	for _, r := range permitted {
		if Denies(sts, r) {
			t.Errorf("both allowlists together deny %s in %s; two NotAction Denies in one document "+
				"intersect, and if nothing survives the account is bricked with no way to recover "+
				"(AUDIT-0 H3)", r.Action, r.Region)
		}
	}

	// And each restriction still bites on its own axis, or the pair enforces
	// nothing and the test above passes trivially.
	if !Denies(sts, Request{Principal: breakGlass, Action: "s3:GetObject", Resource: "*", Region: "eu-west-1"}) {
		t.Error("an allowlisted service outside the allowlisted region is permitted; the region " +
			"restriction enforces nothing")
	}
	if !Denies(sts, Request{Principal: breakGlass, Action: "sagemaker:CreateDomain", Resource: "*", Region: "us-west-2"}) {
		t.Error("a non-allowlisted service inside the allowlisted region is permitted; the service " +
			"restriction enforces nothing")
	}
}

// TestTheTwoAllowlistStatementsShareTheGlobalNamespaces is the invariant the test
// above depends on, stated directly.
//
// The two NotAction lists intersect. What keeps that intersection non-empty is that
// both contain every namespace in the exemption list — so if someone changes one
// statement to build its own list, this fails here with an explanation, rather than
// in the behavioral test with a puzzling denial, or in production with a bricked
// account.
func TestTheTwoAllowlistStatementsShareTheGlobalNamespaces(t *testing.T) {
	region := regionStatement(newAllowSet([]string{"us-west-2"}, "set:r"), testGlobalNamespaces, packOpts())
	service := serviceStatement(newAllowSet([]string{"s3"}, "set:s"), testGlobalNamespaces, packOpts())

	for _, ns := range testGlobalNamespaces {
		want := ns + ":*"
		if !contains(region.NotAction, want) {
			t.Errorf("the region statement's NotAction omits %q", want)
		}
		if !contains(service.NotAction, want) {
			t.Errorf("the service statement's NotAction omits %q; the two NotAction lists intersect, so a "+
				"namespace missing from either is denied by the pair even though each list alone "+
				"permits it", want)
		}
	}
}

// TestAnAllowlistThatIntersectsToNothingIsAConflictNotAPolicy.
//
// Rendering an empty allowlist would produce an SCP denying every call in the
// account — including automat's own baseline work, and including whatever the
// operator would try in order to recover. So it is a conflict report naming the
// artifacts that disagreed.
func TestAnAllowlistThatIntersectsToNothingIsAConflictNotAPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *Merged
		want string
	}{
		{
			name: "regions",
			m:    withGlobalExemptions(&Merged{RegionAllowlist: &AllowSet{Members: []string{}, Sources: []string{"set-a:c1", "set-b:c1"}}}),
			want: "region",
		},
		{
			name: "services",
			m:    withGlobalExemptions(&Merged{ServiceAllowlist: &AllowSet{Members: []string{}, Sources: []string{"set-a:c1", "set-b:c1"}}}),
			want: "service",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe := packError(t, tc.m, packOpts())
			if !strings.Contains(pe.Reason, tc.want) {
				t.Errorf("the error does not say which allowlist collapsed: %v", pe)
			}
			for _, src := range []string{"set-a:c1", "set-b:c1"} {
				if !contains(pe.Sources, src) {
					t.Errorf("the conflict report does not name %s; the operator's first question is "+
						"'which two control sets disagreed' and this cannot answer it", src)
				}
			}
		})
	}
}

// TestAnEmptyAllowlistIsDistinctFromAnAbsentOne is the nil-versus-empty
// distinction at the packer boundary.
//
// Absent means nobody constrained it, and packs to no statement. Empty means two
// control sets constrained it and agreed on nothing, and is an error. Collapsing
// the two would turn a hard conflict into a silently unenforced control.
func TestAnEmptyAllowlistIsDistinctFromAnAbsentOne(t *testing.T) {
	absent := mustPack(t, &Merged{}, packOpts())
	if len(absent.Policies) != 0 {
		t.Fatalf("an absent allowlist must produce no policy, got %d", len(absent.Policies))
	}
	// And empty errors — asserted in the test above. Here the point is only that
	// the two inputs do not behave the same.
	if _, err := Pack(withGlobalExemptions(&Merged{RegionAllowlist: &AllowSet{Members: []string{}}}), packOpts()); err == nil {
		t.Error("an empty (non-nil) region allowlist packed successfully; it means two control sets " +
			"agreed on no region, which as a policy denies every call in the account")
	}
}

// TestAConstrainedSetWithNoExemptionListIsRefused.
//
// Owed by name from withGlobalExemptions and goldenAllowlisted, both of which say
// this is the test that is about the omission.
//
// The refusal exists because the alternative is a rendered policy: a region or
// service Deny whose NotAction spares nothing denies every IAM, STS, and
// Organizations call in the account, including the operator's own attempt to
// detach it. There is no fallback list — see exemptGlobalServices for why a
// compiled-in one would be worse than a refusal — so the packer's only correct
// move is to stop before CreatePolicy, which is what "PLAN time" means here.
func TestAConstrainedSetWithNoExemptionListIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name        string
		m           *Merged
		wantSources []string
	}{
		{
			name:        "regions only",
			m:           &Merged{RegionAllowlist: newAllowSet([]string{"us-west-2"}, "set-a:c1")},
			wantSources: []string{"set-a:c1"},
		},
		{
			name:        "services only",
			m:           &Merged{ServiceAllowlist: newAllowSet([]string{"s3"}, "set-b:c2")},
			wantSources: []string{"set-b:c2"},
		},
		{
			// Both axes constrained by different sets: the operator has two files
			// to look at and the report must name both, because either one could
			// be the set that was supposed to carry the list.
			name: "both, from different sets",
			m: &Merged{
				RegionAllowlist:  newAllowSet([]string{"us-west-2"}, "set-a:c1"),
				ServiceAllowlist: newAllowSet([]string{"s3"}, "set-b:c2"),
			},
			wantSources: []string{"set-a:c1", "set-b:c2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe := packError(t, tc.m, packOpts())
			if !strings.Contains(pe.Reason, "region_deny_exempt_services") {
				t.Errorf("the error does not name the missing field, so it does not say what to add: %v", pe)
			}
			for _, src := range tc.wantSources {
				if !contains(pe.Sources, src) {
					t.Errorf("the refusal does not name %s among the inputs that made the list necessary; "+
						"the operator cannot tell which compiled set to look at", src)
				}
			}
		})
	}
}

// TestAnUnconstrainedSetNeedsNoExemptionList is the other half of the refusal:
// the list is only load-bearing when something restricts regions or services, so
// requiring it unconditionally would refuse every ordinary control set — most of
// which restrict neither.
func TestAnUnconstrainedSetNeedsNoExemptionList(t *testing.T) {
	m := &Merged{Statements: []Statement{
		deny("ProtectRecorder", []string{"config:StopConfigurationRecorder"}, []string{"*"}, nil),
	}}
	got := mustPack(t, m, packOpts())
	if len(got.Policies) != 1 {
		t.Fatalf("expected one policy, got %d", len(got.Policies))
	}
}

// TestAnExemptionListThatIntersectsToNothingIsRefused.
//
// E5's second refusal, and a different failure from the one above: here every
// compiled set stated the fact and they agreed on nothing. Rendering it would
// produce the same bricked account as omitting the list entirely, so it is the
// same refusal — but the remediation is not the same, because "add the list" is
// no help to an operator who has two lists.
//
// nil versus empty carries that distinction (see Merged.RegionDenyExemptServices),
// which is why this is a separate test rather than a case in the table above.
func TestAnExemptionListThatIntersectsToNothingIsRefused(t *testing.T) {
	m := &Merged{
		RegionAllowlist: newAllowSet([]string{"us-west-2"}, "set-a:c1"),
		// Empty and non-nil: two sets stated the fact and the intersection is
		// empty. newAllowSet cannot produce this, which is the point.
		RegionDenyExemptServices: &AllowSet{Members: []string{}, Sources: []string{"set-a:c1", "set-b:c1"}},
	}
	pe := packError(t, m, packOpts())
	if !strings.Contains(pe.Reason, "intersect to nothing") {
		t.Errorf("the error does not say the lists disagreed, so it reads as the missing-list case and "+
			"sends the operator to add a list they already have two of: %v", pe)
	}
	for _, src := range []string{"set-a:c1", "set-b:c1"} {
		if !contains(pe.Sources, src) {
			t.Errorf("the conflict report does not name %s; the sources of an empty intersection are the "+
				"sets that disagreed, which is the only actionable thing about it", src)
		}
	}
	// And the two refusals are distinguishable to a caller reading the text, not
	// only to one comparing struct fields.
	if strings.Contains(pe.Remediation, "will not substitute a built-in list") {
		t.Error("the empty-intersection refusal reuses the missing-list remediation")
	}
}

// TestTheExemptionRefusalHappensBeforeAnyPolicyIsProduced states the "PLAN time"
// half of E5 as something other than a comment.
//
// Pack returns a *Packed and an error; a packer that assembled the documents it
// could and reported the problem alongside them would let a caller that checked
// the count before the error attach a partial policy set. So the refusal must
// yield no policies at all.
func TestTheExemptionRefusalHappensBeforeAnyPolicyIsProduced(t *testing.T) {
	// A set with plenty of ordinary statements that would pack fine on their own,
	// plus one constrained axis with no exemption list.
	m := Merge(goldenFrameworkA(t), goldenFrameworkB(t))
	m.RegionAllowlist = newAllowSet([]string{"us-west-2"}, "set-a:c1")

	got, err := Pack(m, packOpts())
	if err == nil {
		t.Fatal("a constrained set with no exemption list packed successfully")
	}
	if got != nil {
		t.Errorf("Pack returned %d policies alongside the refusal; a caller that checks the count first "+
			"would attach a policy set the packer refused to vouch for", len(got.Policies))
	}
}

// ---------------------------------------------------------------------------
// Determinism and injection
// ---------------------------------------------------------------------------

// TestPackIsDeterministic.
//
// The claim the golden files rest on, and the one that makes the SCP ensure step
// idempotent: a re-vend that recomputes the same policy must produce byte-identical
// output, or `ensure` rewrites a policy nothing asked it to change — and every
// rewrite is an audit event and a chance to fail partway.
func TestPackIsDeterministic(t *testing.T) {
	m := goldenMerged(t)
	first := mustPack(t, m, packOpts())
	for i := 0; i < 8; i++ {
		again := mustPack(t, goldenMerged(t), packOpts())
		if len(again.Policies) != len(first.Policies) {
			t.Fatalf("run %d produced %d policies, first run produced %d",
				i, len(again.Policies), len(first.Policies))
		}
		for j := range first.Policies {
			if again.Policies[j].Document != first.Policies[j].Document {
				t.Fatalf("run %d produced a different document for %s:\n%s\n%s",
					i, first.Policies[j].Name, first.Policies[j].Document, again.Policies[j].Document)
			}
		}
	}
}

// TestPackDoesNotDependOnStatementOrder.
//
// Determinism given the same input is not enough: `compile` may present the same
// control sets in a different order, and the packed policy must not change. The
// merge is order-independent (see the commutativity property), so this checks that
// the packer's own sorting does not reintroduce the dependency.
func TestPackDoesNotDependOnStatementOrder(t *testing.T) {
	forward := goldenMerged(t)
	reversed := goldenMerged(t)
	for i, j := 0, len(reversed.Statements)-1; i < j; i, j = i+1, j-1 {
		reversed.Statements[i], reversed.Statements[j] = reversed.Statements[j], reversed.Statements[i]
	}

	a := mustPack(t, forward, packOpts())
	b := mustPack(t, reversed, packOpts())
	if len(a.Policies) != len(b.Policies) {
		t.Fatalf("reversing the statement order changed the policy count: %d vs %d",
			len(a.Policies), len(b.Policies))
	}
	for i := range a.Policies {
		if a.Policies[i].Document != b.Policies[i].Document {
			t.Errorf("reversing the statement order changed policy %s:\n%s\n%s",
				a.Policies[i].Name, a.Policies[i].Document, b.Policies[i].Document)
		}
	}
}

// TestCatalogValuesCannotBreakOutOfTheDocument.
//
// Catalog files are attacker-controlled in the threat model (CLAUDE.md's audit
// ritual), and every value in them reaches a JSON document. Rendering through
// encoding/json rather than fmt.Sprintf is what makes that safe; this is the test
// that would fail if someone "simplified" the renderer.
func TestCatalogValuesCannotBreakOutOfTheDocument(t *testing.T) {
	hostile := []string{
		`s3:Get"},{"Effect":"Allow","Action":"*","Resource":"*"},{"x":"`,
		`s3:Get\"`,
		"s3:Get\x00Object",
		`s3:Get<script>`,
		"s3:Get\nObject",
	}
	for i, action := range hostile {
		t.Run(fmt.Sprintf("value%d", i), func(t *testing.T) {
			m := &Merged{Statements: []Statement{deny("Hostile", []string{action}, []string{"*"}, nil)}}
			got := mustPack(t, m, packOpts())

			doc := got.Policies[0].Document
			var parsed struct {
				Statement []struct {
					Effect string   `json:"Effect"`
					Action []string `json:"Action"`
				} `json:"Statement"`
			}
			if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
				t.Fatalf("a catalog value produced invalid JSON: %v\n%s", err, doc)
			}
			if len(parsed.Statement) != 1 {
				t.Fatalf("a catalog value injected %d statements into a one-statement policy:\n%s",
					len(parsed.Statement), doc)
			}
			if parsed.Statement[0].Effect != "Deny" {
				t.Fatalf("a catalog value changed the effect to %q:\n%s", parsed.Statement[0].Effect, doc)
			}
			// The value survives as itself, escaped — not mangled into something
			// IAM would compare differently.
			if parsed.Statement[0].Action[0] != action {
				t.Errorf("the action was altered in rendering:\n  in:  %q\n  out: %q",
					action, parsed.Statement[0].Action[0])
			}
		})
	}
}

// TestAmpersandsAndAnglesAreNotHTMLEscaped.
//
// Go's json encoder escapes <, >, and & by default. IAM compares condition values
// literally, so an ARN or action pattern rendered as \u0026 would stop matching —
// and an operator reading the policy text would have no way to see why.
func TestAmpersandsAndAnglesAreNotHTMLEscaped(t *testing.T) {
	m := &Merged{Statements: []Statement{
		deny("Ampersand", []string{"s3:GetObject"}, []string{"arn:aws:s3:::a&b<c>d/*"}, nil),
	}}
	doc := mustPack(t, m, packOpts()).Policies[0].Document
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(doc, escaped) {
			t.Errorf("the document contains the HTML escape %s; IAM compares literally, so the resource "+
				"would not match:\n%s", escaped, doc)
		}
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// wideMerged builds a merged set with n distinct guards, so the statements cannot
// collapse and the packer has to fill policies.
//
// Distinct CONDITIONS rather than distinct actions, because distinct actions under
// one guard would merge into a single statement — correctly — and the packer would
// have nothing to pack. This is a fixture for the quota arithmetic, so it has to
// defeat the merger on purpose.
//
// n is a statement count, not a size. What that packs to depends on the renderer,
// and the mapping moves whenever the rendered form changes — the derived Sid shifted
// every threshold by a dozen characters per statement. Callers that need a
// particular shape use packWhere to search for it rather than naming an n, so this
// fixture stays a knob and not a constant anyone has to maintain.
func wideMerged(t *testing.T, n int) *Merged {
	t.Helper()
	m := &Merged{}
	for i := 0; i < n; i++ {
		m.Statements = append(m.Statements, deny(
			fmt.Sprintf("Deny%03d", i),
			[]string{fmt.Sprintf("service%03d:Action", i)},
			[]string{"*"},
			artifact.Condition{"StringEquals": {"aws:PrincipalTag/unit": {fmt.Sprintf("unit-%03d", i)}}},
		))
	}
	m.Statements = mergeStatements(m.Statements)
	if len(m.Statements) != n {
		t.Fatalf("fixture collapsed %d statements into %d; it is meant to defeat the merger so the "+
			"packer has something to pack", n, len(m.Statements))
	}
	return m
}
