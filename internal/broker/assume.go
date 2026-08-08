// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/config"
)

// sessionName is the RoleSessionName every assumption uses.
//
// A fixed value rather than one carrying a request id or timestamp: CloudTrail
// already records the session name alongside a full request context, and the
// role's trust policy cannot filter on it (ExternalId is what does that work),
// so a varying name would add nothing an operator could act on and would make
// "did automat make this call" a string-prefix question instead of an exact one.
// Matches the form preflight.checkVendorRole already uses for the same role.
const sessionName = "automat-vend"

// Assume assumes roleARN using the ExternalId ref resolves to, and returns an
// aws.Config a caller can build any AWS client from.
//
// ref is a reference in config.ResolveExternalID's form (env:VAR or file:/path),
// not a bare value — this package never sees the ExternalId until the moment it
// resolves one, and never holds it longer than the AssumeRole call it is sent on.
// An empty ref means the role's trust policy requires no ExternalId at all, which
// is a legitimate (if weaker) configuration preflight.checkVendorRole already
// flags on its own.
//
// The returned Config is good for one aws.Config's worth of API calls under the
// assumed role's session — see the package doc for why re-assumption is not
// handled here.
func Assume(ctx context.Context, api awsapi.STSAPI, roleARN, ref, region string) (aws.Config, error) {
	in := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
	}
	if ref != "" {
		externalID, err := config.ResolveExternalID(ref)
		if err != nil {
			return aws.Config{}, fmt.Errorf("resolve the ExternalId for %s: %w", roleARN, err)
		}
		in.ExternalId = aws.String(externalID)
	}

	out, err := api.AssumeRole(ctx, in)
	if err != nil {
		return aws.Config{}, assumeError(err, roleARN, ref != "")
	}
	if out.Credentials == nil {
		// Not reachable against the real SDK — AssumeRole either errors or
		// returns credentials — but a fake that forgets to set them must not
		// produce a Config that looks usable and fails opaquely on the first
		// real call.
		return aws.Config{}, fmt.Errorf("AssumeRole on %s returned no credentials", roleARN)
	}

	creds := *out.Credentials
	provider := credentials.NewStaticCredentialsProvider(
		aws.ToString(creds.AccessKeyId),
		aws.ToString(creds.SecretAccessKey),
		aws.ToString(creds.SessionToken),
	)
	return aws.Config{Region: region, Credentials: provider}, nil
}

// assumeError turns an AssumeRole failure into remediation naming the exact
// missing grant (CLAUDE.md rule 7), following preflight.checkVendorRole's
// wording for the same failure so an operator sees one consistent explanation
// whether the assumption failed during preflight or during a vend.
//
// AWS returns undifferentiated AccessDenied for "role does not trust this
// principal", "ExternalId is wrong", and "ExternalId was required but omitted" —
// awsfake.STS reproduces that deliberately so remediation text cannot rely on a
// distinction AWS itself will not make in production. What differs by
// sentExternalID is only which grant sentence is more likely to be the fix, not
// which happened; both branches still name both requirements.
func assumeError(err error, roleARN string, sentExternalID bool) error {
	grant := "the management account must (1) trust this account's caller in the role's trust " +
		"policy and (2) require the same sts:ExternalId configured in external_id_ref; " +
		"`automat setup --request` emits both, ready to apply"
	if sentExternalID {
		grant += ". An ExternalId was sent and the assumption still failed — AWS does not say " +
			"which of the trust policy, the ExternalId, or the caller's permissions was wrong, " +
			"so check all three"
	} else {
		grant += ". No ExternalId was sent (external_id_ref is unset); the role may require one"
	}
	return awsapi.Denied(err, "sts:AssumeRole", roleARN, "", grant)
}
