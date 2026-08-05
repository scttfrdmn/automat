// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// IAM fakes awsapi.IAMAPI.
//
// Allowed lists the actions the simulator reports as allowed; everything else is
// implicitDeny. Note what this fake cannot express, deliberately: an SCP. The
// real SimulatePrincipalPolicy does not evaluate them either (DESIGN §3, fact 9),
// so a fake that could would let automat's report claim a certainty AWS never
// provides. The gap is the finding, not a limitation to work around.
type IAM struct {
	Recorder

	// Allowed is the set of actions the caller's identity policies permit.
	Allowed map[string]bool
	// Err, if set, fails the call. A member account may not even be allowed to
	// simulate, which preflight must report as "could not determine" rather than
	// as a denial of the simulated action.
	Err error
}

// NewIAM returns an IAM fake allowing the given actions.
func NewIAM(allowed ...string) *IAM {
	m := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		m[a] = true
	}
	return &IAM{Allowed: m}
}

// SimulatePrincipalPolicy implements awsapi.IAMAPI.
func (f *IAM) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput,
	_ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	f.Record("SimulatePrincipalPolicy")
	if f.Err != nil {
		return nil, f.Err
	}
	results := make([]iamtypes.EvaluationResult, 0, len(in.ActionNames))
	for _, action := range in.ActionNames {
		decision := iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
		if f.Allowed[action] {
			decision = iamtypes.PolicyEvaluationDecisionTypeAllowed
		}
		res := iamtypes.EvaluationResult{
			EvalActionName: aws.String(action),
			EvalDecision:   decision,
		}
		if len(in.ResourceArns) > 0 {
			res.EvalResourceName = aws.String(in.ResourceArns[0])
		}
		results = append(results, res)
	}
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: results}, nil
}

var _ awsapi.IAMAPI = (*IAM)(nil)
