// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	sqtypes "github.com/aws/aws-sdk-go-v2/service/servicequotas/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// Quota fakes awsapi.QuotaAPI.
//
// Values maps "<serviceCode>/<quotaCode>" to the quota value. A quota absent
// from the map returns NoSuchResourceException, and Err covers the more common
// case of the caller simply not being allowed to read quotas — preflight must
// degrade to "unknown" there rather than to a number, because an invented
// default is exactly the kind of confident wrong answer that gets a vend planned
// and then blocked.
type Quota struct {
	Recorder

	Values map[string]float64
	Err    error
}

// NewQuota returns a Quota fake reporting the default accounts-per-organization
// quota, which is the low value that makes this call worth making at all
// (DESIGN §3, fact 11).
func NewQuota() *Quota {
	return &Quota{Values: map[string]float64{"organizations/L-29A0C5DF": 10}}
}

// GetServiceQuota implements awsapi.QuotaAPI.
func (f *Quota) GetServiceQuota(_ context.Context, in *servicequotas.GetServiceQuotaInput,
	_ ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error) {
	f.Record("GetServiceQuota")
	if f.Err != nil {
		return nil, f.Err
	}
	key := aws.ToString(in.ServiceCode) + "/" + aws.ToString(in.QuotaCode)
	v, ok := f.Values[key]
	if !ok {
		return nil, &APIError{
			Code:    "NoSuchResourceException",
			Message: "The specified resource does not exist.",
		}
	}
	return &servicequotas.GetServiceQuotaOutput{Quota: &sqtypes.ServiceQuota{
		QuotaCode:   in.QuotaCode,
		ServiceCode: in.ServiceCode,
		QuotaName:   aws.String("Default maximum number of accounts"),
		Value:       aws.Float64(v),
		Adjustable:  true,
		Unit:        aws.String("None"),
	}}, nil
}

var _ awsapi.QuotaAPI = (*Quota)(nil)
