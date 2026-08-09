// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import "fmt"

// SchemaVersion is the evidence-manifest schema version this package writes.
//
// Bumping it is a schema event: CLAUDE.md rule 6 and schema/CHANGELOG.md.
const SchemaVersion = "1.0.0"

// ZeroHash is records[0].previous_sha256 — 64 zeros.
//
// A distinguished value rather than an empty string, because "" would make "the
// first record" and "a record whose link was dropped" the same document.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Operation is what a record says was done. The vocabulary is closed and mirrors
// the schema's enum.
type Operation string

// The operations a record may name. One per mutating command plus verify and
// assess, neither of which writes anything to AWS but are worth recording as
// having run, and custody-transfer, which ends the chain.
const (
	OpInit             Operation = "init"
	OpSetup            Operation = "setup"
	OpAccountCreate    Operation = "account-create"
	OpAccountMove      Operation = "account-move"
	OpOUEnsure         Operation = "ou-ensure"
	OpSCPEnsure        Operation = "scp-ensure"
	OpBaselineApply    Operation = "baseline-apply"
	OpAttestationWrite Operation = "attestation-write"
	OpVerify           Operation = "verify"
	OpAssess           Operation = "assess"
	OpReclaim          Operation = "reclaim"
	OpCustodyTransfer  Operation = "custody-transfer"
)

// AllOperations is the closed set, in the schema's order.
var AllOperations = []Operation{
	OpInit, OpSetup, OpAccountCreate, OpAccountMove, OpOUEnsure, OpSCPEnsure,
	OpBaselineApply, OpAttestationWrite, OpVerify, OpAssess, OpReclaim, OpCustodyTransfer,
}

// Outcome is how an operation ended.
type Outcome string

// The outcomes. Parked is not a kind of failure: it means the operation left real
// AWS state behind that a later `vend --resume` must find (DESIGN §5), and an
// operator's inventory is built from these.
const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeParked  Outcome = "parked"
)

// AllOutcomes is the closed set.
var AllOutcomes = []Outcome{OutcomeSuccess, OutcomeFailure, OutcomeParked}

// Role is the capacity an attestation over a profile document was made in —
// environment or obligation; the vocabulary is shared.
//
// The same closed five-value vocabulary the environment and obligation profile
// schemas use, and the reason it is closed is that these are four unrelated
// claims of wildly different
// weight: "X wrote this", "Y adopted it for its own use", "Z read it", and "the
// format validated". A reader shown one undifferentiated checkmark infers the
// strongest available, which is how "the JSON parsed" becomes "the university
// approved this". No role means approved, certified, or compliant, and none may be
// added that does (DESIGN §11a).
type Role string

// The roles.
const (
	RoleAuthoredBy        Role = "authored-by"
	RoleAdoptedBy         Role = "adopted-by"
	RoleReviewedBy        Role = "reviewed-by"
	RoleInterpretedBy     Role = "interpreted-by"
	RoleFormatValidatedBy Role = "format-validated-by"
)

// AllRoles is the closed set.
var AllRoles = []Role{
	RoleAuthoredBy, RoleAdoptedBy, RoleReviewedBy, RoleInterpretedBy, RoleFormatValidatedBy,
}

// Manifest is one evidence manifest: the header plus the chain.
type Manifest struct {
	SchemaVersion string   `json:"schema_version"`
	Meta          Meta     `json:"manifest"`
	Records       []Record `json:"records"`
}

// Meta identifies the manifest. Per-account manifests use the account id as the
// id, so a manifest found on its own says which account it is about.
type Meta struct {
	ID             string `json:"id"`
	AccountID      string `json:"account_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	CreatedAt      string `json:"created_at"`
	// GenesisSHA is records[0].RecordSHA, set once by Append when the first record
	// lands and never changed after. No omitempty: absent-and-required must round-trip
	// as an error, not as a silently accepted zero value, on a field whose entire job
	// is to be checked against — see the schema's genesis_sha256 for what it catches
	// and, as importantly, what it does not (AUDIT-2 H3).
	GenesisSHA string `json:"genesis_sha256"`
}

// Record is one appended operation.
//
// Field order matters only for MarshalIndented's readability; hashing goes
// through canonical form, which sorts keys.
type Record struct {
	Sequence   int            `json:"sequence"`
	Timestamp  string         `json:"timestamp"`
	Operation  Operation      `json:"operation"`
	Outcome    Outcome        `json:"outcome,omitempty"`
	Operator   Operator       `json:"operator"`
	RequestID  string         `json:"request_id,omitempty"`
	Target     *Target        `json:"target,omitempty"`
	Artifact   *DocRef        `json:"artifact,omitempty"`
	EnvProfile *EnvProfileRef `json:"environment_profile,omitempty"`
	// Determinations names the operator-determinations document an `assess`
	// record's finding drew from, by id and content hash — the reference
	// schema/CHANGELOG.md's "Pre-publication change to evidence-manifest/v1:
	// `operation` gains `assess`" entry named while OpAssess was being
	// scoped, ahead of internal/assess existing to produce the hash: "a
	// reference to the operator-determinations file it read, following
	// evidence.DocRef's existing id + content_sha256 shape". Absent when
	// assess ran with no --determinations file (every practice silently NOT
	// MET), the same absent-is-honest convention Result.Determinations
	// itself follows (schema/assessment-result-v1.schema.json's own
	// $comment on that field).
	Determinations *DocRef      `json:"determinations,omitempty"`
	Enforcement    *Enforcement `json:"enforcement,omitempty"`
	Err            *RecordError `json:"error,omitempty"`
	Custody        *Custody     `json:"custody_transfer,omitempty"`
	ToolVersion    string       `json:"tool_version"`
	PreviousSHA    string       `json:"previous_sha256"`
	RecordSHA      string       `json:"record_sha256"`
	Signature      *Signature   `json:"signature,omitempty"`
}

// Operator is the principal that performed the operation.
type Operator struct {
	ARN         string `json:"arn"`
	AccountID   string `json:"account_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	AssumedRole string `json:"assumed_role,omitempty"`
}

// Target is what the operation acted on.
type Target struct {
	AccountID   string `json:"account_id,omitempty"`
	AccountName string `json:"account_name,omitempty"`
	OUID        string `json:"ou_id,omitempty"`
	Region      string `json:"region,omitempty"`
}

// DocRef names a hashed document by id and content hash. Used for the control
// artifact and, inside a custody transfer, for the final artifact handed over.
//
// The content hash is what makes the reference checkable rather than a label: a
// record naming only an id is a record whose subject can be edited afterwards.
type DocRef struct {
	ID            string `json:"id"`
	ContentSHA256 string `json:"content_sha256"`
	SchemaVersion string `json:"schema_version,omitempty"`
}

// EnvProfileRef names the ENVIRONMENT profile in force, plus the attestations over
// it that were VERIFIED — never the ones merely present in the file (DESIGN §11a).
//
// Named for the document type rather than just "profile" because automat has
// three — environment, obligation, classification — and a record that says only
// "profile" leaves the auditor it exists for to guess which kind of claim it is
// making. The environment profile is the one `vend` consumes.
type EnvProfileRef struct {
	ID            string `json:"id"`
	ContentSHA256 string `json:"content_sha256"`
	SchemaVersion string `json:"schema_version,omitempty"`
	// ReviewBy is the environment profile's own review-by date, copied rather than
	// looked up: an evidence record has to be readable years later without its
	// inputs, so an auditor can see the environment profile was already past review
	// when the account was vended without needing the file.
	ReviewBy string `json:"review_by,omitempty"`
	// VerifiedSignatures is REQUIRED in the wire form and an EMPTY SLICE IS THE
	// NORMAL VALUE: automat verifies nothing in v1, so it records the empty set.
	// No omitempty, deliberately — an absent field would read as "unknown", and
	// the difference between "nothing was verified" and "the question was never
	// asked" is exactly the one an evidence record must not blur. A reader
	// resolves which an empty set means from the record's own tool_version.
	VerifiedSignatures []VerifiedSignature `json:"verified_signatures"`
}

// VerifiedSignature is one attestation over an environment profile that verified:
// the identity and the capacity it attested in, and nothing else.
//
// PROVENANCE ONLY. Recording an entry here says who stood behind the environment
// profile document, never that it is correct, applicable to this account, or
// approved for this use. What made the identity acceptable is an operator
// determination against a trust policy the operator maintains; automat ships no
// trust anchor and no default accepted identity, so this never means "automat
// trusts this signer".
type VerifiedSignature struct {
	Role     Role   `json:"role"`
	Identity string `json:"identity"`
	// VerifiedAgainst names the trust policy the determination came from, so a
	// reader can ask what that policy said. Empty in v1, which loads none.
	VerifiedAgainst string `json:"verified_against,omitempty"`
}

// Enforcement is what was actually attached or deployed.
type Enforcement struct {
	SCPARNs            []string `json:"scp_arns,omitempty"`
	ConformancePackARN string   `json:"conformance_pack_arn,omitempty"`
	ConfigRuleNames    []string `json:"config_rule_names,omitempty"`
	RegionSet          []string `json:"region_set,omitempty"`
	ServiceSet         []string `json:"service_set,omitempty"`
	AttestationIDs     []string `json:"attestation_ids,omitempty"`
}

// empty reports whether an enforcement block asserts nothing. An empty block in a
// record is noise a reader has to rule out, and it perturbs the hash for no
// reason, so canonicalization drops it.
func (e *Enforcement) empty() bool {
	return e == nil || (len(e.SCPARNs) == 0 && e.ConformancePackARN == "" &&
		len(e.ConfigRuleNames) == 0 && len(e.RegionSet) == 0 && len(e.ServiceSet) == 0 &&
		len(e.AttestationIDs) == 0)
}

// RecordError is present when the outcome is failure or parked.
//
// It carries the remediation text, not a bare message: a permission failure must
// say which action, which resource, and what grant would fix it (CLAUDE.md rule
// 7), and that text is part of the evidence record rather than log output. An
// operator reading a parked account out of the manifest six weeks later has only
// this.
type RecordError struct {
	Message     string `json:"message"`
	Action      string `json:"action,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Custody records why and to whom custody of this manifest passed. Required on a
// custody-transfer record and forbidden on every other kind.
type Custody struct {
	Transferee string `json:"transferee"`
	// EffectiveDate is a date, not a timestamp, and deliberately distinct from the
	// record's own: custody passing is a policy fact usually agreed before or
	// recorded after the moment it takes effect.
	EffectiveDate       string `json:"effective_date"`
	Reason              string `json:"reason"`
	FinalArtifact       DocRef `json:"final_artifact"`
	SuccessorManifestID string `json:"successor_manifest_id,omitempty"`
}

// Signature is a detached signature over a record's record_sha256.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	// Value is base64 signature bytes, standard encoding with padding.
	Value string `json:"value"`
}

// Algorithm names a signing algorithm the schema admits.
type Algorithm string

// The algorithms. Only the first is implemented; the KMS forms are named so
// adopting one is not a schema version event (DESIGN §11).
const (
	AlgEd25519      Algorithm = "ed25519"
	AlgKMSRSAPSS256 Algorithm = "aws-kms-rsassa-pss-sha-256"
	AlgKMSECDSA256  Algorithm = "aws-kms-ecdsa-sha-256"
)

// AllAlgorithms is the closed set.
var AllAlgorithms = []Algorithm{AlgEd25519, AlgKMSRSAPSS256, AlgKMSECDSA256}

// IsCustodyTransfer reports whether this record is the terminal kind.
func (r *Record) IsCustodyTransfer() bool { return r.Operation == OpCustodyTransfer }

// Last returns the final record, or nil for an empty chain.
func (m *Manifest) Last() *Record {
	if len(m.Records) == 0 {
		return nil
	}
	return &m.Records[len(m.Records)-1]
}

// Closed reports whether the chain has been deliberately ended by a
// custody-transfer record. A closed manifest takes no further records.
func (m *Manifest) Closed() bool {
	last := m.Last()
	return last != nil && last.IsCustodyTransfer()
}

// Parked returns the records whose outcome is parked and which name an account,
// most recent first.
//
// This is what `list` reads to show parked accounts and what `vend --resume`
// consults: the account exists in AWS, so a record of it is the only thing
// standing between an operator and an account nothing points at.
func (m *Manifest) Parked() []Record {
	var out []Record
	for i := len(m.Records) - 1; i >= 0; i-- {
		r := m.Records[i]
		if r.Outcome == OutcomeParked {
			out = append(out, r)
		}
	}
	return out
}

// ForRequest returns the records carrying the given vend request id, in chain
// order. A resumed vend uses this to learn what the original run already did.
func (m *Manifest) ForRequest(requestID string) []Record {
	if requestID == "" {
		// Not "every record with no request id". A caller asking for "" is asking
		// a question with no answer, and returning the un-attributed records would
		// answer a different one.
		return nil
	}
	var out []Record
	for _, r := range m.Records {
		if r.RequestID == requestID {
			out = append(out, r)
		}
	}
	return out
}

// safe renders an untrusted string for an error message.
//
// The same discipline as artifact.safe, for the same reason: a manifest is loaded
// from disk and its prose fields are attacker-controlled in the threat model,
// while this package's own errors are read by an operator deciding whether a
// chain is sound. %q escapes newlines and control bytes and marks the value as
// data.
func safe(s string) string {
	const max = 120
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}
