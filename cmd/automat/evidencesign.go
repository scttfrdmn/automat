// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/scttfrdmn/automat/internal/config"
	"github.com/scttfrdmn/automat/internal/evidence"
)

// evidenceSigner builds the Signer every evidence-writing command passes to
// Manifest.Append, from the context's evidence_kms_key_id/
// evidence_kms_algorithm pair (DESIGN §11's KMS drop-in). Returns nil, nil
// when neither is set — an unsigned record is a valid document (Signer's
// own doc comment), and whether signatures are required is a policy
// decision above this package, not something a missing config value should
// silently work around.
//
// config.validateEvidenceKMS already enforces that the two fields are
// both-or-neither and that the algorithm is one of evidence's own two
// committed KMS forms, so the only new failure mode here is the KMS client
// itself.
func evidenceSigner(ctx context.Context, g *globals, region, profile string,
	orgCtx config.Context) (evidence.Signer, error) {
	if orgCtx.EvidenceKMSKeyID == "" {
		return nil, nil
	}
	kmsAPI, err := g.kmsClient(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	signer, err := evidence.NewKMSSigner(kmsAPI, orgCtx.EvidenceKMSKeyID,
		evidence.Algorithm(orgCtx.EvidenceKMSAlgorithm))
	if err != nil {
		return nil, fmt.Errorf("evidence_kms_key_id/evidence_kms_algorithm in the config file: %w", err)
	}
	return signer, nil
}
