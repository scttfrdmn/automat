// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/evidence"
)

// TestEvidenceKMSAlgorithmsMatchTheEvidencePackage keeps evidenceKMSAlgorithms
// (a restated closed set, since this package cannot import internal/evidence
// for its Algorithm type without drawing a dependency edge for two string
// literals) in step with evidence.AllAlgorithms's own KMS members. Drift here
// would mean a config value this file accepts as valid is one
// evidence.KMSSigner then refuses, or the reverse.
func TestEvidenceKMSAlgorithmsMatchTheEvidencePackage(t *testing.T) {
	var want []string
	for _, a := range evidence.AllAlgorithms {
		if a == evidence.AlgEd25519 {
			continue
		}
		want = append(want, string(a))
	}
	if !stringSlicesEqual(evidenceKMSAlgorithms, want) {
		t.Errorf("evidenceKMSAlgorithms = %v, want %v (evidence.AllAlgorithms minus AlgEd25519)",
			evidenceKMSAlgorithms, want)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func kmsContextConfig(body string) string {
	return "[context.c]\n" + body + "\n"
}

func TestValidateEvidenceKMSAcceptsBothFieldsPresent(t *testing.T) {
	body := kmsContextConfig(`evidence_kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/abcd1234"
evidence_kms_algorithm = "aws-kms-rsassa-pss-sha-256"`)
	if _, err := Decode([]byte(body), "test.toml"); err != nil {
		t.Fatalf("Decode rejected a well-formed evidence_kms_* pair: %v", err)
	}
}

func TestValidateEvidenceKMSAcceptsBothFieldsAbsent(t *testing.T) {
	body := kmsContextConfig(`org = "o-abcdefghij"`)
	if _, err := Decode([]byte(body), "test.toml"); err != nil {
		t.Fatalf("Decode rejected a context with neither evidence_kms_* field: %v", err)
	}
}

func TestValidateEvidenceKMSRefusesAKeyWithNoAlgorithm(t *testing.T) {
	body := kmsContextConfig(`evidence_kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/abcd1234"`)
	_, err := Decode([]byte(body), "test.toml")
	if err == nil {
		t.Fatal("Decode accepted evidence_kms_key_id with no evidence_kms_algorithm")
	}
	if !strings.Contains(err.Error(), "evidence_kms_algorithm") {
		t.Errorf("error does not name the missing field: %v", err)
	}
}

func TestValidateEvidenceKMSRefusesAnAlgorithmWithNoKey(t *testing.T) {
	body := kmsContextConfig(`evidence_kms_algorithm = "aws-kms-rsassa-pss-sha-256"`)
	_, err := Decode([]byte(body), "test.toml")
	if err == nil {
		t.Fatal("Decode accepted evidence_kms_algorithm with no evidence_kms_key_id")
	}
	if !strings.Contains(err.Error(), "evidence_kms_key_id") {
		t.Errorf("error does not name the missing field: %v", err)
	}
}

func TestValidateEvidenceKMSRefusesAnUnknownAlgorithm(t *testing.T) {
	body := kmsContextConfig(`evidence_kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/abcd1234"
evidence_kms_algorithm = "aws-kms-made-up-256"`)
	_, err := Decode([]byte(body), "test.toml")
	if err == nil {
		t.Fatal("Decode accepted an evidence_kms_algorithm value outside the closed set")
	}
}

func TestValidateEvidenceKMSRefusesAKeyIDWithAControlCharacter(t *testing.T) {
	body := kmsContextConfig("evidence_kms_key_id = \"arn:aws:kms:us-east-1:111122223333:key/x\ty\"\n" +
		"evidence_kms_algorithm = \"aws-kms-rsassa-pss-sha-256\"")
	if _, err := Decode([]byte(body), "test.toml"); err == nil {
		t.Fatal("Decode accepted a key id containing a tab, want a refusal — CLAUDE.md rule 8")
	}
}

func TestValidateEvidenceKMSAcceptsABareAlias(t *testing.T) {
	body := kmsContextConfig(`evidence_kms_key_id = "alias/automat-evidence"
evidence_kms_algorithm = "aws-kms-ecdsa-sha-256"`)
	if _, err := Decode([]byte(body), "test.toml"); err != nil {
		t.Fatalf("Decode rejected a bare alias key id: %v", err)
	}
}
