// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// The write fakes get their own tests, which looks like testing test
// infrastructure and is not.
//
// Every claim in this file is a claim about AWS, and it is the only place those
// claims are checkable — CLAUDE.md rule 1 means no test in this repository ever
// reaches the real API. `internal/org`'s tests will assert that automat handles
// asynchronous creation, root-landing, and a DuplicatePolicyAttachment on re-run;
// all three of those tests pass vacuously if the fake does not produce the
// behavior. A fake that is wrong in the permissive direction certifies code that
// cannot work, and nothing downstream can catch it.
//
// So these tests are written against DESIGN §3's load-bearing facts by number. If
// one of them is wrong about AWS, the fix is a DESIGN §3 amendment surfaced per
// CLAUDE.md rule 2, not a quiet edit here.

const (
	testOrgID     = "o-exampleorg"
	testMgmtAcct  = "111111111111"
	testOwnerTag  = "automat:managed-by=automat"
	testOwnerKey  = "automat:managed-by"
	testOwnerVal  = "automat"
	scpDocument   = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
	requiredTagA  = "automat:vended-by"
	requiredTagB  = "automat:ou"
	testAccountOU = "ou-exam-research"
)

func ctx() context.Context { return context.Background() }

// vendAccount runs the create-and-poll dance and returns the new account id.
func vendAccount(t *testing.T, f *OrgVend, name, email string, tags map[string]string) string {
	t.Helper()
	var in organizations.CreateAccountInput
	in.AccountName = aws.String(name)
	in.Email = aws.String(email)
	for k, v := range tags {
		in.Tags = append(in.Tags, orgtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	out, err := f.CreateAccount(ctx(), &in)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	reqID := aws.ToString(out.CreateAccountStatus.Id)

	for i := 0; i < 20; i++ {
		st, err := f.DescribeCreateAccountStatus(ctx(),
			&organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: aws.String(reqID)})
		if err != nil {
			t.Fatalf("DescribeCreateAccountStatus: %v", err)
		}
		switch st.CreateAccountStatus.State {
		case orgtypes.CreateAccountStateSucceeded:
			return aws.ToString(st.CreateAccountStatus.AccountId)
		case orgtypes.CreateAccountStateFailed:
			t.Fatalf("create failed: %s", st.CreateAccountStatus.FailureReason)
		}
	}
	t.Fatal("create never completed")
	return ""
}

// TestCreateAccountIsAsynchronousAndLandsUnderTheRoot is DESIGN §3 facts 4 and 6
// in one assertion, and it is the fact the vend flow is shaped around.
//
// CreateAccount returns before the account exists, and when it does exist it is
// under the ROOT — not in the OU the caller wants. That is why DESIGN §7 has a
// separate move step and why DESIGN §5 documents "parked" as a real state an
// operator will see. A fake that returned a finished account in the destination
// would make the move step look like ceremony and the parked-account handling look
// like paranoia.
func TestCreateAccountIsAsynchronousAndLandsUnderTheRoot(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	f := NewOrgVend(s)

	out, err := f.CreateAccount(ctx(), &organizations.CreateAccountInput{
		AccountName: aws.String("research-a"),
		Email:       aws.String("research-a@example.edu"),
	})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if got := out.CreateAccountStatus.State; got != orgtypes.CreateAccountStateInProgress {
		t.Errorf("CreateAccount returned state %s, want IN_PROGRESS: the account does not "+
			"exist yet, and code that reads AccountId here reads nil", got)
	}
	if out.CreateAccountStatus.AccountId != nil {
		t.Error("CreateAccount returned an AccountId, which the real API does not: " +
			"a fake that hands one over immediately lets a missing poll loop pass")
	}
	if len(s.AccountIDs()) != 0 {
		t.Error("the account exists before it was polled for")
	}

	id := vendAccount(t, f, "research-b", "research-b@example.edu", nil)
	if got := s.ParentOf(id); got != s.RootID {
		t.Errorf("new account is under %q, want the root %q (DESIGN §3 fact 4): "+
			"CreateAccount cannot be OU-constrained, which is the entire reason "+
			"MoveAccount is in the vend flow", got, s.RootID)
	}
}

// TestCreateAccountFailsAsynchronously. The failure arrives at the poll, not at
// the call, and a duplicate email is the failure an operator will actually hit —
// every account needs a globally unique one (DESIGN §3 fact 11) and a research
// group's naming pattern collides eventually.
func TestCreateAccountFailsAsynchronously(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	f := NewOrgVend(s)
	s.SeedAccount("existing", "taken@example.edu", s.RootID)

	out, err := f.CreateAccount(ctx(), &organizations.CreateAccountInput{
		AccountName: aws.String("dup"),
		Email:       aws.String("taken@example.edu"),
	})
	if err != nil {
		t.Fatalf("CreateAccount returned an immediate error for a duplicate email; the "+
			"real API accepts the request and fails at the poll, so code checking only "+
			"this return believes it succeeded: %v", err)
	}

	reqID := aws.ToString(out.CreateAccountStatus.Id)
	var final *orgtypes.CreateAccountStatus
	for i := 0; i < 20; i++ {
		st, err := f.DescribeCreateAccountStatus(ctx(),
			&organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: aws.String(reqID)})
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if st.CreateAccountStatus.State != orgtypes.CreateAccountStateInProgress {
			final = st.CreateAccountStatus
			break
		}
	}
	if final == nil {
		t.Fatal("request never terminated")
	}
	if final.State != orgtypes.CreateAccountStateFailed {
		t.Errorf("state %s, want FAILED", final.State)
	}
	if final.FailureReason != orgtypes.CreateAccountFailureReasonEmailAlreadyExists {
		t.Errorf("FailureReason %q, want EMAIL_ALREADY_EXISTS", final.FailureReason)
	}
	if got := len(s.AccountIDs()); got != 1 {
		t.Errorf("a failed create left %d accounts, want the 1 that was seeded", got)
	}
}

// TestMandatoryCreateTagsAreEnforcedAsADenial.
//
// The vendor role's CreateAccount grant carries an aws:RequestTag condition
// requiring automat:vended-by and automat:ou (DESIGN §3 fact 5;
// internal/bundle/role.go). AWS reports a failed condition as AccessDenied, and
// the distinction matters for CLAUDE.md rule 7: automat must tell the operator
// which grant is missing, and a "bad input" classification would send them to
// debug their own command line instead.
func TestMandatoryCreateTagsAreEnforcedAsADenial(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	s.RequiredCreateTags = []string{requiredTagA, requiredTagB}
	f := NewOrgVend(s)

	_, err := f.CreateAccount(ctx(), &organizations.CreateAccountInput{
		AccountName: aws.String("untagged"),
		Email:       aws.String("untagged@example.edu"),
		Tags: []orgtypes.Tag{
			{Key: aws.String(requiredTagA), Value: aws.String("111111111111")},
		},
	})
	if err == nil {
		t.Fatal("CreateAccount without automat:ou succeeded; the vendor role's " +
			"aws:RequestTag condition refuses it, so code written against this fake would " +
			"be written against a grant that does not exist")
	}
	if !awsapi.IsAccessDenied(err) {
		t.Errorf("error is %v (code %q), want an access denial: AWS reports a failed "+
			"request-tag condition as AccessDenied, and rule 7 needs automat to name the "+
			"grant rather than blame the input", err, awsapi.APIErrorCode(err))
	}
	if !strings.Contains(err.Error(), requiredTagB) {
		t.Errorf("the denial does not name the missing tag %q: %v", requiredTagB, err)
	}
}

// TestMoveAccountRequiresKnowingWhereTheAccountIs. SourceParentId is mandatory in
// the real API, which is why the flow reads ListParents first — and why a resumed
// vend cannot blindly replay its earlier call.
func TestMoveAccountRequiresKnowingWhereTheAccountIs(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	other := s.SeedOU("Other", s.RootID)
	f := NewOrgVend(s)
	acct := vendAccount(t, f, "a", "a@example.edu", nil)

	_, err := f.MoveAccount(ctx(), &organizations.MoveAccountInput{
		AccountId:           aws.String(acct),
		DestinationParentId: aws.String(ou),
		SourceParentId:      aws.String(other),
	})
	if err == nil {
		t.Fatal("MoveAccount accepted a wrong SourceParentId")
	}
	if got := awsapi.APIErrorCode(err); got != "SourceParentNotFoundException" {
		t.Errorf("code %q, want SourceParentNotFoundException", got)
	}

	if _, err := f.MoveAccount(ctx(), &organizations.MoveAccountInput{
		AccountId:           aws.String(acct),
		DestinationParentId: aws.String(ou),
		SourceParentId:      aws.String(s.RootID),
	}); err != nil {
		t.Fatalf("MoveAccount with the right source: %v", err)
	}
	if got := s.ParentOf(acct); got != ou {
		t.Errorf("account is under %q after the move, want %q", got, ou)
	}
}

// TestBothReadingsOfAMoveToWhereTheAccountAlreadyIsAreReachable.
//
// Which one AWS does is unresolved (docs/open-questions.md Q12) and it is the
// behavior `vend --resume` turns on: a resumed vend re-runs the move against an
// account already in place. Ensure-semantics code has to pass either way, so both
// readings have to be producible. This test asserts the knob works, not which
// reading is right — asserting the latter would be claiming an answer only a live
// org has.
func TestBothReadingsOfAMoveToWhereTheAccountAlreadyIsAreReachable(t *testing.T) {
	for _, errors := range []bool{false, true} {
		s := NewOrgState(testOrgID, testMgmtAcct)
		s.MoveToSamePlaceErrors = errors
		ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
		f := NewOrgVend(s)
		acct := vendAccount(t, f, "a", "a@example.edu", nil)

		mv := &organizations.MoveAccountInput{
			AccountId:           aws.String(acct),
			DestinationParentId: aws.String(ou),
			SourceParentId:      aws.String(s.RootID),
		}
		if _, err := f.MoveAccount(ctx(), mv); err != nil {
			t.Fatalf("first move: %v", err)
		}
		// The re-run, with the source now stale — which is itself part of the
		// resumability problem.
		_, err := f.MoveAccount(ctx(), &organizations.MoveAccountInput{
			AccountId:           aws.String(acct),
			DestinationParentId: aws.String(ou),
			SourceParentId:      aws.String(ou),
		})
		switch {
		case errors && err == nil:
			t.Error("MoveToSamePlaceErrors is set but the redundant move succeeded")
		case !errors && err != nil:
			t.Errorf("MoveToSamePlaceErrors is clear but the redundant move failed: %v", err)
		}
		if got := s.ParentOf(acct); got != ou {
			t.Errorf("account moved away from %q to %q", ou, got)
		}
	}
}

// TestOUDepthLimitIsFiveLevels is DESIGN §3 fact 10. The profile may ask for
// intermediate OUs, so this is a limit automat's own input can drive it into.
func TestOUDepthLimitIsFiveLevels(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	f := NewOrgVend(s)

	parent := s.RootID
	for i := 1; i <= 5; i++ {
		out, err := f.CreateOrganizationalUnit(ctx(), &organizations.CreateOrganizationalUnitInput{
			Name:     aws.String("level" + string(rune('0'+i))),
			ParentId: aws.String(parent),
		})
		if err != nil {
			t.Fatalf("creating OU at level %d: %v", i, err)
		}
		parent = aws.ToString(out.OrganizationalUnit.Id)
	}

	_, err := f.CreateOrganizationalUnit(ctx(), &organizations.CreateOrganizationalUnitInput{
		Name:     aws.String("level6"),
		ParentId: aws.String(parent),
	})
	if err == nil {
		t.Fatal("a sixth level of OU was created; DESIGN §3 fact 10 caps it at five")
	}
	var cv *orgtypes.ConstraintViolationException
	if !errors.As(err, &cv) || cv.Reason != orgtypes.ConstraintViolationExceptionReasonOuDepthLimitExceeded {
		t.Errorf("error is %v, want a ConstraintViolationException with reason "+
			"OU_DEPTH_LIMIT_EXCEEDED so automat can distinguish it from a denial", err)
	}
}

// TestCreateOrganizationalUnitRefusesADuplicateName is what forces ensure-semantics
// to be look-then-create rather than create-and-swallow. Worth pinning because the
// error is a duplicate-*name* error, not a duplicate-id error: the name is
// automat's only handle on an OU it created in an earlier run.
func TestCreateOrganizationalUnitRefusesADuplicateName(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	f := NewOrgVend(s)
	in := &organizations.CreateOrganizationalUnitInput{
		Name: aws.String("Research"), ParentId: aws.String(s.RootID),
	}
	if _, err := f.CreateOrganizationalUnit(ctx(), in); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := f.CreateOrganizationalUnit(ctx(), in)
	if got := awsapi.APIErrorCode(err); got != "DuplicateOrganizationalUnitException" {
		t.Errorf("second create returned %v (code %q), want DuplicateOrganizationalUnit"+
			"Exception — an ensure operation must read before it writes", err, got)
	}
}

// TestTheVendorRoleCannotPlaceAnAccountOutsideItsOU.
//
// The template restricts MoveAccount by destination OU ARN and
// CreateOrganizationalUnit by parent ARN. This is the property the onboarding
// bundle's blast-radius argument rests on, asserted against the behavior rather
// than against the template's text — internal/bundle already tests the text, and
// two tests of the same sentence would not have caught a code path that assumed
// the grant were wider.
func TestTheVendorRoleCannotPlaceAnAccountOutsideItsOU(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	research := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	sub := s.SeedOU("Sub", research)
	central := s.SeedOU("CentralIT", s.RootID)

	f := &OrgVend{State: s, DenyOutsideOU: research}
	acct := vendAccount(t, f, "a", "a@example.edu", nil)

	for _, tc := range []struct {
		name, dst string
		wantDeny  bool
	}{
		{"the delegated OU", research, false},
		{"a descendant of it", sub, false},
		{"central IT's OU", central, true},
		{"the root", s.RootID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := s.ParentOf(acct)
			_, err := f.MoveAccount(ctx(), &organizations.MoveAccountInput{
				AccountId:           aws.String(acct),
				DestinationParentId: aws.String(tc.dst),
				SourceParentId:      aws.String(src),
			})
			switch {
			case tc.wantDeny && err == nil:
				t.Errorf("moving into %s succeeded; the vendor role is scoped to %q and its "+
					"descendants, and every blast-radius sentence in the bundle depends on that",
					tc.name, research)
			case !tc.wantDeny && err != nil:
				t.Errorf("moving into %s was denied: %v", tc.name, err)
			}
		})
	}

	if _, err := f.CreateOrganizationalUnit(ctx(), &organizations.CreateOrganizationalUnitInput{
		Name: aws.String("Sneaky"), ParentId: aws.String(central),
	}); !awsapi.IsAccessDenied(err) {
		t.Errorf("creating an OU under central IT's OU returned %v, want a denial", err)
	}
}

// TestTheDelegateCannotTouchAPolicyItDoesNotOwn is the behavioral half of
// AUDIT-1's C1.
//
// internal/bundle asserts the delegation policy's conditions read the RESOURCE
// tag. This asserts what that means when exercised: an untagged policy — central
// IT's institutional SCP — is not updatable, not attachable, and cannot be tagged
// into automat's ownership. The last one is the whole finding: if tagging were
// gated on the request tag, applying automat's tag to central IT's SCP would
// succeed and every other condition would then pass.
func TestTheDelegateCannotTouchAPolicyItDoesNotOwn(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	institutional := s.SeedPolicy("institutional-floor", scpDocument, nil)
	f := NewDelegatedOrgPolicy(s, testOwnerTag, ou)

	if _, err := f.UpdatePolicy(ctx(), &organizations.UpdatePolicyInput{
		PolicyId: aws.String(institutional),
		Content:  aws.String(`{"Version":"2012-10-17","Statement":[]}`),
	}); !awsapi.IsAccessDenied(err) {
		t.Errorf("UpdatePolicy on central IT's SCP returned %v, want a denial. The "+
			"delegation gates modification on the resource tag; a policy automat did not "+
			"create does not carry it.", err)
	}
	if got := s.PolicyContent(institutional); got != scpDocument {
		t.Error("central IT's policy content changed")
	}

	if _, err := f.TagResource(ctx(), &organizations.TagResourceInput{
		ResourceId: aws.String(institutional),
		Tags:       []orgtypes.Tag{{Key: aws.String(testOwnerKey), Value: aws.String(testOwnerVal)}},
	}); !awsapi.IsAccessDenied(err) {
		t.Errorf("TagResource applied automat's owner tag to central IT's SCP (%v). This "+
			"is AUDIT-1's C1 exactly: a condition that reads a tag the caller may write "+
			"constrains nothing, and update/delete/detach all follow from this one call.", err)
	}
	if _, ok := s.TagsOf(institutional)[testOwnerKey]; ok {
		t.Error("central IT's policy now carries automat's owner tag")
	}

	if _, err := f.AttachPolicy(ctx(), &organizations.AttachPolicyInput{
		PolicyId: aws.String(institutional), TargetId: aws.String(ou),
	}); !awsapi.IsAccessDenied(err) {
		t.Errorf("AttachPolicy with central IT's SCP returned %v, want a denial", err)
	}
}

// TestTheDelegateCanManageItsOwnPolicyInsideItsOU is the other direction: the
// scoping has to leave automat able to do its job. A fake that denied everything
// would pass the test above and be useless.
func TestTheDelegateCanManageItsOwnPolicyInsideItsOU(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	f := NewDelegatedOrgPolicy(s, testOwnerTag, ou)

	out, err := f.CreatePolicy(ctx(), &organizations.CreatePolicyInput{
		Name:        aws.String("automat-cmmc-l1"),
		Description: aws.String("automat control set"),
		Content:     aws.String(scpDocument),
		Type:        orgtypes.PolicyTypeServiceControlPolicy,
		Tags:        []orgtypes.Tag{{Key: aws.String(testOwnerKey), Value: aws.String(testOwnerVal)}},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	pid := aws.ToString(out.Policy.PolicySummary.Id)

	if _, err := f.UpdatePolicy(ctx(), &organizations.UpdatePolicyInput{
		PolicyId: aws.String(pid), Content: aws.String(scpDocument + " "),
	}); err != nil {
		t.Errorf("UpdatePolicy on automat's own policy: %v — ensure-semantics corrects "+
			"drift in place rather than replacing, because replacing means a window with "+
			"the control detached", err)
	}
	if _, err := f.AttachPolicy(ctx(), &organizations.AttachPolicyInput{
		PolicyId: aws.String(pid), TargetId: aws.String(ou),
	}); err != nil {
		t.Errorf("AttachPolicy to the delegated OU: %v", err)
	}
	if got := s.AttachedTo(ou); len(got) != 1 || got[0] != pid {
		t.Errorf("attachments on %s are %v, want just %s", ou, got, pid)
	}
}

// TestAttachingTwiceIsAnErrorNotASilentSuccess. AWS is explicit here —
// DuplicatePolicyAttachment — so an ensure operation must read the target's
// attachments first or treat this code as success. It cannot simply retry.
func TestAttachingTwiceIsAnErrorNotASilentSuccess(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	pid := s.SeedPolicy("automat-x", scpDocument, map[string]string{testOwnerKey: testOwnerVal})
	f := NewOrgPolicy(s)

	in := &organizations.AttachPolicyInput{PolicyId: aws.String(pid), TargetId: aws.String(ou)}
	if _, err := f.AttachPolicy(ctx(), in); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	_, err := f.AttachPolicy(ctx(), in)
	if got := awsapi.APIErrorCode(err); got != "DuplicatePolicyAttachmentException" {
		t.Errorf("second attach returned %v (code %q), want DuplicatePolicyAttachment"+
			"Exception", err, got)
	}
	if got := len(s.AttachedTo(ou)); got != 1 {
		t.Errorf("the OU has %d attachments after a duplicate attach, want 1", got)
	}
}

// TestTheFivePolicyLimitIsReachable. Union output plus region plus service plus
// baseline-protection is four SCPs before anything unusual happens, so the packer
// meets this limit in ordinary use. DESIGN §3 fact 11 puts practical quotas in the
// load-bearing list for this reason.
func TestTheFivePolicyLimitIsReachable(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	f := NewOrgPolicy(s)

	for i := 0; i < 5; i++ {
		pid := s.SeedPolicy("p"+string(rune('a'+i)), scpDocument,
			map[string]string{testOwnerKey: testOwnerVal})
		if _, err := f.AttachPolicy(ctx(), &organizations.AttachPolicyInput{
			PolicyId: aws.String(pid), TargetId: aws.String(ou),
		}); err != nil {
			t.Fatalf("attaching policy %d: %v", i, err)
		}
	}
	sixth := s.SeedPolicy("psix", scpDocument, map[string]string{testOwnerKey: testOwnerVal})
	_, err := f.AttachPolicy(ctx(), &organizations.AttachPolicyInput{
		PolicyId: aws.String(sixth), TargetId: aws.String(ou),
	})
	var cv *orgtypes.ConstraintViolationException
	if !errors.As(err, &cv) {
		t.Fatalf("a sixth SCP attached to one target, or failed with %v; AWS caps it at "+
			"five and the packer has to pack for that", err)
	}
	if cv.Reason != orgtypes.ConstraintViolationExceptionReasonMaxPolicyTypeAttachmentLimitExceeded {
		t.Errorf("reason %q, want MAX_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED", cv.Reason)
	}
}

// TestAPolicyOverTheSizeLimitIsRefused. 5120 bytes for an SCP, and the packer's
// job is to stay under it. A fake without the limit would let an unpackable set
// through and the failure would surface in a live org.
func TestAPolicyOverTheSizeLimitIsRefused(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	f := NewOrgPolicy(s)
	_, err := f.CreatePolicy(ctx(), &organizations.CreatePolicyInput{
		Name:        aws.String("huge"),
		Description: aws.String("d"),
		Content:     aws.String(strings.Repeat("x", s.PolicySizeLimit+1)),
		Type:        orgtypes.PolicyTypeServiceControlPolicy,
	})
	var cv *orgtypes.ConstraintViolationException
	if !errors.As(err, &cv) ||
		cv.Reason != orgtypes.ConstraintViolationExceptionReasonPolicyContentLimitExceeded {
		t.Errorf("error is %v, want POLICY_CONTENT_LIMIT_EXCEEDED", err)
	}
}

// TestAnSCPCannotExistWithoutTheAllFeatureSet is DESIGN §3 fact 8 from the
// CreatePolicy side, and TestInitMustEnableTheSCPPolicyTypeSeparately is the other
// half. Together they are the reason `init` is not just CreateOrganization.
func TestAnSCPCannotExistWithoutTheAllFeatureSet(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	s.FeatureSet = orgtypes.OrganizationFeatureSetConsolidatedBilling
	f := NewOrgPolicy(s)
	_, err := f.CreatePolicy(ctx(), &organizations.CreatePolicyInput{
		Name: aws.String("x"), Description: aws.String("d"),
		Content: aws.String(scpDocument), Type: orgtypes.PolicyTypeServiceControlPolicy,
	})
	var cv *orgtypes.ConstraintViolationException
	if !errors.As(err, &cv) ||
		cv.Reason != orgtypes.ConstraintViolationExceptionReasonOrganizationNotInAllFeaturesMode {
		t.Errorf("error is %v, want ORGANIZATION_NOT_IN_ALL_FEATURES_MODE (DESIGN §3 "+
			"fact 8)", err)
	}
}

// TestInitMustEnableTheSCPPolicyTypeSeparately is the trap in `init`.
//
// A fresh organization is in ALL features mode and has the SCP policy type
// DISABLED on its root. CreatePolicy works. AttachPolicy is the call that fails —
// and if it did not, every control automat attached would exist, look attached,
// and enforce nothing. That is the worst failure shape available to this tool: an
// account that reports compliant and is not.
func TestInitMustEnableTheSCPPolicyTypeSeparately(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	init := NewOrgInit(s)

	if _, err := init.CreateOrganization(ctx(), &organizations.CreateOrganizationInput{
		FeatureSet: orgtypes.OrganizationFeatureSetAll,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if s.SCPEnabled {
		t.Fatal("SCPs are enabled straight after CreateOrganization; AWS requires " +
			"EnablePolicyType on the root, and a fake that skipped it would let init ship " +
			"without it — producing accounts whose controls exist and enforce nothing")
	}

	ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	pol := NewOrgPolicy(s)
	pid := s.SeedPolicy("automat-x", scpDocument, map[string]string{testOwnerKey: testOwnerVal})
	if _, err := pol.AttachPolicy(ctx(), &organizations.AttachPolicyInput{
		PolicyId: aws.String(pid), TargetId: aws.String(ou),
	}); awsapi.APIErrorCode(err) != "PolicyTypeNotEnabledException" {
		t.Errorf("attaching before EnablePolicyType returned %v, want "+
			"PolicyTypeNotEnabledException", err)
	}

	if _, err := init.EnablePolicyType(ctx(), &organizations.EnablePolicyTypeInput{
		RootId: aws.String(s.RootID), PolicyType: orgtypes.PolicyTypeServiceControlPolicy,
	}); err != nil {
		t.Fatalf("EnablePolicyType: %v", err)
	}
	if _, err := pol.AttachPolicy(ctx(), &organizations.AttachPolicyInput{
		PolicyId: aws.String(pid), TargetId: aws.String(ou),
	}); err != nil {
		t.Errorf("attaching after EnablePolicyType: %v", err)
	}
}

// TestReRunningInitIsRefusedRatherThanSilentlyDuplicated. Both calls are
// non-idempotent in the AWS sense: a second one errors. CLAUDE.md rule 4 means
// automat's `init` must treat these two codes as success, and it can only be
// written to if the fake produces them.
func TestReRunningInitIsRefusedRatherThanSilentlyDuplicated(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	init := NewOrgInit(s)
	in := &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}
	if _, err := init.CreateOrganization(ctx(), in); err != nil {
		t.Fatalf("first CreateOrganization: %v", err)
	}
	if got := awsapi.APIErrorCode(mustErr(t, func() error {
		_, err := init.CreateOrganization(ctx(), in)
		return err
	})); got != "AlreadyInOrganizationException" {
		t.Errorf("second CreateOrganization returned code %q, want "+
			"AlreadyInOrganizationException — which ensure-semantics reads as success", got)
	}

	ept := &organizations.EnablePolicyTypeInput{
		RootId: aws.String(s.RootID), PolicyType: orgtypes.PolicyTypeServiceControlPolicy,
	}
	if _, err := init.EnablePolicyType(ctx(), ept); err != nil {
		t.Fatalf("first EnablePolicyType: %v", err)
	}
	if got := awsapi.APIErrorCode(mustErr(t, func() error {
		_, err := init.EnablePolicyType(ctx(), ept)
		return err
	})); got != "PolicyTypeAlreadyEnabledException" {
		t.Errorf("second EnablePolicyType returned code %q, want "+
			"PolicyTypeAlreadyEnabledException", got)
	}
}

// TestInitRefusesAnythingButTheAllFeatureSet. Stricter than AWS, deliberately:
// AWS accepts CONSOLIDATED_BILLING and automat has no reason to ever send it, so a
// test that did should fail loudly rather than proceed into an org where no SCP can
// exist. The fake's doc comment records this as the one place it is intentionally
// harsher than the service.
func TestInitRefusesAnythingButTheAllFeatureSet(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	init := NewOrgInit(s)
	_, err := init.CreateOrganization(ctx(), &organizations.CreateOrganizationInput{
		FeatureSet: orgtypes.OrganizationFeatureSetConsolidatedBilling,
	})
	if err == nil {
		t.Fatal("CreateOrganization accepted CONSOLIDATED_BILLING")
	}
	if init.Created {
		t.Error("the refused call still marked the org as created")
	}
}

// TestEveryPaginatedListNeedsDraining.
//
// Each of these returns a NextToken when there is more, and a caller that reads
// one page gets a truncated answer with no error. For automat that means an ensure
// operation concluding a policy is not attached when it is, which produces a
// duplicate-attach error at best and a wrong compliance claim at worst.
//
// The test does not assert that automat drains them — no automat code calls these
// yet. It asserts the FAKE paginates, so that the tests written in tasks #11 and
// #13 are written against an API that can truncate.
func TestEveryPaginatedListNeedsDraining(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	if s.PageSize != 2 {
		t.Fatalf("PageSize is %d; this test assumes 2", s.PageSize)
	}
	ou := s.SeedOUWithID(testAccountOU, "Research", s.RootID)
	for i := 0; i < 5; i++ {
		s.SeedOU("sub"+string(rune('a'+i)), ou)
		s.SeedAccount("acct"+string(rune('a'+i)), string(rune('a'+i))+"@example.edu", ou)
		pid := s.SeedPolicy("pol"+string(rune('a'+i)), scpDocument,
			map[string]string{testOwnerKey: testOwnerVal})
		s.SeedAttachment(pid, ou)
	}

	vend, pol := NewOrgVend(s), NewOrgPolicy(s)

	t.Run("ListOrganizationalUnitsForParent", func(t *testing.T) {
		var got []string
		var token *string
		for {
			out, err := vend.ListOrganizationalUnitsForParent(ctx(),
				&organizations.ListOrganizationalUnitsForParentInput{
					ParentId: aws.String(ou), NextToken: token,
				})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if token == nil && out.NextToken == nil {
				t.Fatal("the first page carried no NextToken with 5 items and PageSize 2; " +
					"a caller that ignores pagination would pass every test written here")
			}
			for _, o := range out.OrganizationalUnits {
				got = append(got, aws.ToString(o.Id))
			}
			if out.NextToken == nil {
				break
			}
			token = out.NextToken
		}
		if len(got) != 5 {
			t.Errorf("drained %d OUs, want 5", len(got))
		}
		if len(dedupe(got)) != len(got) {
			t.Errorf("pagination repeated an item: %v", got)
		}
	})

	t.Run("ListAccountsForParent", func(t *testing.T) {
		var got []string
		var token *string
		for {
			out, err := vend.ListAccountsForParent(ctx(),
				&organizations.ListAccountsForParentInput{ParentId: aws.String(ou), NextToken: token})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if token == nil && out.NextToken == nil {
				t.Fatal("no NextToken on the first page")
			}
			for _, a := range out.Accounts {
				got = append(got, aws.ToString(a.Id))
			}
			if out.NextToken == nil {
				break
			}
			token = out.NextToken
		}
		if len(got) != 5 {
			t.Errorf("drained %d accounts, want 5", len(got))
		}
	})

	t.Run("ListPoliciesForTarget", func(t *testing.T) {
		var got []string
		var token *string
		for {
			out, err := pol.ListPoliciesForTarget(ctx(), &organizations.ListPoliciesForTargetInput{
				TargetId:  aws.String(ou),
				Filter:    orgtypes.PolicyTypeServiceControlPolicy,
				NextToken: token,
			})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if token == nil && out.NextToken == nil {
				t.Fatal("no NextToken on the first page; an ensure operation reading one " +
					"page would conclude an attached policy is not attached")
			}
			for _, p := range out.Policies {
				got = append(got, aws.ToString(p.Id))
			}
			if out.NextToken == nil {
				break
			}
			token = out.NextToken
		}
		if len(got) != 5 {
			t.Errorf("drained %d policies, want 5", len(got))
		}
	})

	t.Run("ListPolicies", func(t *testing.T) {
		var got []string
		var token *string
		for {
			out, err := pol.ListPolicies(ctx(), &organizations.ListPoliciesInput{
				Filter: orgtypes.PolicyTypeServiceControlPolicy, NextToken: token,
			})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if token == nil && out.NextToken == nil {
				t.Fatal("no NextToken on the first page")
			}
			for _, p := range out.Policies {
				got = append(got, aws.ToString(p.Id))
			}
			if out.NextToken == nil {
				break
			}
			token = out.NextToken
		}
		if len(got) != 5 {
			t.Errorf("drained %d policies, want 5", len(got))
		}
	})

	t.Run("ListTagsForResource", func(t *testing.T) {
		// Tags need their own fixture: the seeded policies carry one key each, and one
		// key does not span a page. Truncation here is how automat would decide its
		// own owner tag is absent from a resource that has it — and then either
		// refuse to manage its own policy or, worse, tag it again from scratch.
		pid := s.PolicyIDByName("pola")
		vendFake := NewOrgVend(s)
		for _, k := range []string{"automat:ou", "automat:artifact-sha256", "automat:profile", "automat:cost-center"} {
			if _, err := vendFake.TagResource(ctx(), &organizations.TagResourceInput{
				ResourceId: aws.String(pid),
				Tags:       []orgtypes.Tag{{Key: aws.String(k), Value: aws.String("v")}},
			}); err != nil {
				t.Fatalf("seeding tag %q: %v", k, err)
			}
		}

		var got []string
		var token *string
		for {
			out, err := pol.ListTagsForResource(ctx(),
				&organizations.ListTagsForResourceInput{ResourceId: aws.String(pid), NextToken: token})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if token == nil && out.NextToken == nil {
				t.Fatal("no NextToken on the first page")
			}
			for _, tg := range out.Tags {
				got = append(got, aws.ToString(tg.Key))
			}
			if out.NextToken == nil {
				break
			}
			token = out.NextToken
		}
		// The owner tag from SeedPolicy plus the four added here.
		if len(got) != 5 {
			t.Errorf("drained %d tag keys, want 5: %v", len(got), got)
		}
		if !contains(got, testOwnerKey) {
			t.Errorf("the owner tag %q is not in the drained set %v; a caller reading one "+
				"page would conclude automat does not own its own policy", testOwnerKey, got)
		}
	})
}

// TestTheTwoCredentialsShareOneOrganizationAndNotOneCallLog is the property the
// shared-state design exists for, and the reason each fake keeps its own Recorder.
//
// A vend in MEMBER state runs on two credentials at once. The state has to be
// shared or the policy half could not attach to the OU the vend half created. The
// call logs have to be separate or "the delegated credential issued no account
// operation" would be unassertable — and that is the claim the whole delegation
// model makes.
func TestTheTwoCredentialsShareOneOrganizationAndNotOneCallLog(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	root := s.RootID
	vend := NewOrgVend(s)
	pol := NewOrgPolicy(s)

	out, err := vend.CreateOrganizationalUnit(ctx(), &organizations.CreateOrganizationalUnitInput{
		Name: aws.String("Research"), ParentId: aws.String(root),
	})
	if err != nil {
		t.Fatalf("CreateOrganizationalUnit: %v", err)
	}
	ou := aws.ToString(out.OrganizationalUnit.Id)

	// The policy client can see and use what the vend client made.
	pc, err := pol.CreatePolicy(ctx(), &organizations.CreatePolicyInput{
		Name: aws.String("automat-x"), Description: aws.String("d"),
		Content: aws.String(scpDocument), Type: orgtypes.PolicyTypeServiceControlPolicy,
		Tags: []orgtypes.Tag{{Key: aws.String(testOwnerKey), Value: aws.String(testOwnerVal)}},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := pol.AttachPolicy(ctx(), &organizations.AttachPolicyInput{
		PolicyId: pc.Policy.PolicySummary.Id, TargetId: aws.String(ou),
	}); err != nil {
		t.Fatalf("AttachPolicy to an OU the other credential created: %v", err)
	}

	// And the logs are separate.
	if got := vend.CallCount("CreatePolicy"); got != 0 {
		t.Errorf("the vend credential's log shows %d CreatePolicy calls; DESIGN §5 says "+
			"the vendor role carries no policy actions, and a shared log would make that "+
			"unassertable", got)
	}
	if got := pol.CallCount("CreateOrganizationalUnit"); got != 0 {
		t.Errorf("the policy credential's log shows %d CreateOrganizationalUnit calls; "+
			"that action cannot be delegated at all (DESIGN §3 fact 2)", got)
	}
}

// TestIDsAreDeterministic. Phase 2's acceptance criterion includes golden vend
// output, which is impossible if an account id changes per run — or, worse,
// possible only by leaving the ids out of the golden file, which removes them from
// the assertion.
func TestIDsAreDeterministic(t *testing.T) {
	ids := func() []string {
		s := NewOrgState(testOrgID, testMgmtAcct)
		f := NewOrgVend(s)
		var out []string
		for _, n := range []string{"a", "b", "c"} {
			out = append(out, vendAccount(t, f, n, n+"@example.edu", nil))
		}
		out = append(out, s.SeedOU("Research", s.RootID))
		return out
	}
	first, second := ids(), ids()
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Errorf("two identical runs produced different ids:\n  %v\n  %v", first, second)
	}
}

// TestTagsSetAtCreationSurviveALaterTagCall. The two tags conditions read are set
// once, at CreateAccount, through aws:RequestTag; the three cost-allocation keys
// change on a re-vend. So TagResource has to be additive — a fake that replaced the
// tag set would let code ship that silently drops the tags its own conditions
// depend on.
func TestTagsSetAtCreationSurviveALaterTagCall(t *testing.T) {
	s := NewOrgState(testOrgID, testMgmtAcct)
	f := NewOrgVend(s)
	acct := vendAccount(t, f, "a", "a@example.edu", map[string]string{
		requiredTagA: testMgmtAcct,
		requiredTagB: testAccountOU,
	})

	if _, err := f.TagResource(ctx(), &organizations.TagResourceInput{
		ResourceId: aws.String(acct),
		Tags: []orgtypes.Tag{
			{Key: aws.String("automat:artifact-sha256"), Value: aws.String("abc")},
		},
	}); err != nil {
		t.Fatalf("TagResource: %v", err)
	}

	tags := s.TagsOf(acct)
	for _, k := range []string{requiredTagA, requiredTagB, "automat:artifact-sha256"} {
		if _, ok := tags[k]; !ok {
			t.Errorf("tag %q is gone after a later TagResource call; the call is additive "+
				"in AWS, and two of these keys are read by conditions in the delegation", k)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func mustErr(t *testing.T, f func() error) error {
	t.Helper()
	err := f()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	return err
}
