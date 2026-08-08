// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"regexp"
	"strings"
)

// Problem is one validation failure.
//
// The same shape as artifact.Problem and for the same reason (CLAUDE.md rule 7):
// Path says where, Message says what is wrong, Fix says what to change. A
// validation failure an operator cannot act on is a bug in the validator.
type Problem struct {
	Path    string
	Message string
	Fix     string
}

func (p Problem) Error() string {
	if p.Fix == "" {
		return fmt.Sprintf("%s: %s", p.Path, p.Message)
	}
	return fmt.Sprintf("%s: %s — %s", p.Path, p.Message, p.Fix)
}

// ValidationError collects every problem found in one pass.
type ValidationError struct {
	Subject  string
	Problems []Problem
}

func (v *ValidationError) Error() string {
	var sb strings.Builder
	subject := v.Subject
	if subject == "" {
		subject = "evidence manifest"
	}
	fmt.Fprintf(&sb, "%s is invalid (%d problem", subject, len(v.Problems))
	if len(v.Problems) != 1 {
		sb.WriteByte('s')
	}
	sb.WriteString("):")
	for _, p := range v.Problems {
		fmt.Fprintf(&sb, "\n  - %s", p.Error())
	}
	return sb.String()
}

// Unwrap exposes the problems to errors.Is/As traversal.
func (v *ValidationError) Unwrap() []error {
	out := make([]error, len(v.Problems))
	for i, p := range v.Problems {
		out[i] = p
	}
	return out
}

type problems struct{ list []Problem }

func (p *problems) add(path, message, fix string) {
	p.list = append(p.list, Problem{Path: path, Message: message, Fix: fix})
}

// Patterns mirror schema/evidence-manifest-v1.schema.json. The schema
// conformance test is what keeps them in step.
var (
	reSemver    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	reDate      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	reAccountID = regexp.MustCompile(`^[0-9]{12}$`)
	reOrgID     = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	reDocID     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	reOUID      = regexp.MustCompile(`^(ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|r-[0-9a-z]{4,32})$`)
	reRegion    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	reService   = regexp.MustCompile(`^[a-z0-9-]+$`)
	reBase64    = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	// Round-trip fields (CLAUDE.md rule 8): identities automat WRITES that a person
	// is expected to read back and type. Narrower than prose, and not for injection
	// reasons — argument construction is the CLI's problem. This refuses to record a
	// value whose purpose is to travel through human hands into a shell.
	//
	// reRoundTripID covers ids automat mints: manifest.id, request_id,
	// successor_manifest_id. reRoundTripRef covers references it does not mint and so
	// cannot reduce to a plain id — a KMS key ARN has colons and slashes — and admits
	// exactly the punctuation those forms need and no character that could end a
	// shell word.
	reRoundTripID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	// 256 rather than the 2048 an ARN may reach: Go's regexp caps a repeat count at
	// 1000, so the wider bound is not expressible here, and a bound the Go layer
	// cannot state is a bound the schema must not state either — rule 8 wants both
	// layers to agree. 256 clears every real key reference (a KMS key ARN is ~90
	// characters, an alias far less) with room to spare.
	reRoundTripRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/+=@-]{0,255}$`)
	// Prose fields are printed back in reports, and a control byte in one forges a
	// line of that report. Refused here rather than escaped at every render site.
	reProse = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
)

// maxProse mirrors the schema's maxLength on $defs/prose.
const maxProse = 1024

// maxVerifiedSignatures mirrors the schema's maxItems. Sixteen because a list long
// enough to skim past is one nobody reads.
const maxVerifiedSignatures = 16

// Validate checks the manifest against every constraint the schema expresses plus
// the chain-level ones it cannot, returning a *ValidationError listing all of
// them.
//
// Reports every problem rather than stopping at the first: an operator handed a
// manifest that will not load wants the whole list.
func (m *Manifest) Validate() error {
	var p problems

	if !reSemver.MatchString(m.SchemaVersion) {
		p.add("schema_version", fmt.Sprintf("%s is not plain semver", safe(m.SchemaVersion)),
			"use a MAJOR.MINOR.PATCH string; this package writes "+SchemaVersion)
	}
	m.Meta.validate(&p)

	if len(m.Records) == 0 {
		p.add("records", "the chain is empty",
			"a manifest exists to record operations; a manifest with none is a file with no subject")
	}
	for i := range m.Records {
		m.Records[i].validate(fmt.Sprintf("records[%d]", i), &p)
	}
	m.validateChain(&p)
	m.validateHeaderAgainstRecords(&p)

	if len(p.list) == 0 {
		return nil
	}
	subject := "evidence manifest"
	if m.Meta.ID != "" {
		subject = "evidence manifest " + safe(m.Meta.ID)
	}
	return &ValidationError{Subject: subject, Problems: p.list}
}

func (mt *Meta) validate(p *problems) {
	if mt.ID == "" {
		p.add("manifest.id", "is empty",
			"a per-account manifest uses the account id, so a manifest found on its own says "+
				"which account it is about")
	} else if !reRoundTripID.MatchString(mt.ID) {
		p.add("manifest.id", fmt.Sprintf("%s is not a usable manifest id", safe(mt.ID)),
			"use letters, digits, dot, dash, and underscore: this id is printed in every report "+
				"this manifest appears in and is what a person names it by, so it has to survive "+
				"being retyped and being selected by double-click")
	}
	if mt.AccountID != "" && !reAccountID.MatchString(mt.AccountID) {
		p.add("manifest.account_id", fmt.Sprintf("%s is not a 12-digit AWS account id", safe(mt.AccountID)),
			"use the account id CreateAccount returned")
	}
	if mt.OrganizationID != "" && !reOrgID.MatchString(mt.OrganizationID) {
		p.add("manifest.organization_id", fmt.Sprintf("%s is not an organization id", safe(mt.OrganizationID)),
			"organization ids look like o-abc1234567")
	}
	if !reTimestamp.MatchString(mt.CreatedAt) {
		p.add("manifest.created_at", fmt.Sprintf("%s is not a second-precision UTC timestamp", safe(mt.CreatedAt)),
			"use the 2026-08-05T00:00:00Z form; sub-second and offset forms would break deterministic hashing")
	}
	if !reSHA256.MatchString(mt.GenesisSHA) {
		p.add("manifest.genesis_sha256", fmt.Sprintf("%s is not a sha256 hex digest", safe(mt.GenesisSHA)),
			"this is records[0].record_sha256, set once when the first record is appended and never "+
				"changed after — Append sets it; do not set it by hand")
	}
}

// validate checks one record against the schema's constraints, including the
// custody-transfer pairing rules.
func (r *Record) validate(path string, p *problems) {
	if r.Sequence < 0 {
		p.add(path+".sequence", fmt.Sprintf("is %d", r.Sequence), "sequence is zero-based and never negative")
	}
	if !reTimestamp.MatchString(r.Timestamp) {
		p.add(path+".timestamp", fmt.Sprintf("%s is not a second-precision UTC timestamp", safe(r.Timestamp)),
			"use the 2026-08-05T00:00:00Z form")
	}
	if !knownOperation(r.Operation) {
		p.add(path+".operation", fmt.Sprintf("%s is not one of the recorded operations", safe(string(r.Operation))),
			"the vocabulary is closed: "+joinOperations())
	}
	if r.Outcome != "" && !knownOutcome(r.Outcome) {
		p.add(path+".outcome", fmt.Sprintf("%s is not an outcome", safe(string(r.Outcome))),
			"use success, failure, or parked; parked means real AWS state was left behind for --resume to find")
	}
	if r.Operator.ARN == "" {
		p.add(path+".operator.arn", "is empty",
			"a record with no principal cannot say who did the thing it records")
	}
	if r.Operator.AccountID != "" && !reAccountID.MatchString(r.Operator.AccountID) {
		p.add(path+".operator.account_id", fmt.Sprintf("%s is not a 12-digit AWS account id",
			safe(r.Operator.AccountID)), "use the id STS reported")
	}
	if !reProse.MatchString(r.ToolVersion) {
		p.add(path+".tool_version", fmt.Sprintf("%s is empty or not printable single-line text",
			safe(r.ToolVersion)), "use the value `automat version` prints")
	}
	if r.RequestID != "" && !reRoundTripID.MatchString(r.RequestID) {
		p.add(path+".request_id", fmt.Sprintf("%s is not a usable request id", safe(r.RequestID)),
			"use letters, digits, dot, dash, and underscore: an operator has to retype this value "+
				"as `automat vend --resume <request-id>`, and a shell metacharacter in it is a "+
				"record that misleads them into running something else")
	}
	if !reSHA256.MatchString(r.PreviousSHA) {
		p.add(path+".previous_sha256", fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(r.PreviousSHA)),
			"the first record's link is 64 zeros; every later one is its predecessor's record_sha256")
	}
	if !reSHA256.MatchString(r.RecordSHA) {
		p.add(path+".record_sha256", fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(r.RecordSHA)),
			"compute it with evidence.ComputeRecordHash; it covers the canonicalized record with "+
				"record_sha256 and signature omitted")
	}

	r.Target.validate(path+".target", p)
	r.Artifact.validate(path+".artifact", p)
	r.EnvProfile.validate(path+".environment_profile", p)
	r.Enforcement.validate(path+".enforcement", p)
	r.Err.validate(path+".error", p)
	r.Signature.validate(path+".signature", p)
	r.validateOutcomePairing(path, p)
	r.validateCustodyPairing(path, p)
}

// validateOutcomePairing holds the error block and the outcome to each other.
//
// The schema does not express this pair, and it is the one that decides whether an
// operator can act on a parked account six weeks later: a parked record with no
// error names an account that exists in AWS and says nothing about why it stopped,
// which is a worse artifact than no record at all — it proves something was left
// behind and withholds what.
func (r *Record) validateOutcomePairing(path string, p *problems) {
	failed := r.Outcome == OutcomeFailure || r.Outcome == OutcomeParked
	switch {
	case failed && r.Err == nil:
		p.add(path+".error", fmt.Sprintf("is absent on a %s record", r.Outcome),
			"record the message, the action, the resource, and the remediation: a parked account "+
				"exists in AWS, and this record is the only thing an operator has to act on")
	case !failed && r.Err != nil:
		p.add(path+".error", "is present on a successful record",
			"an operation that succeeded has nothing to remediate; if it partly failed, record the "+
				"failure as its own record rather than annotating the success")
	}
}

// validateCustodyPairing enforces the schema's custody-transfer rules in Go.
//
// Duplicated from the schema deliberately: automat writes manifests with these
// types and never round-trips them through the JSON Schema on the write path, so a
// rule that lives only in schema/ is a rule automat's own writer is not held to.
func (r *Record) validateCustodyPairing(path string, p *problems) {
	if !r.IsCustodyTransfer() {
		if r.Custody != nil {
			p.add(path+".custody_transfer", fmt.Sprintf("is present on a %s record", r.Operation),
				"a transfer must be the operation, not a passenger on one: on any other record "+
					"nothing reads for it, and the chain would end where no reader looks")
		}
		return
	}
	if r.Custody == nil {
		p.add(path+".custody_transfer", "is absent on a custody-transfer record",
			"name the transferee, the effective date, the reason, and the artifact being handed "+
				"over; a chain that ends without them is indistinguishable from one that was truncated")
	} else {
		r.Custody.validate(path+".custody_transfer", p)
	}
	if r.Outcome != "" && r.Outcome != OutcomeSuccess {
		p.add(path+".outcome", fmt.Sprintf("is %s on a custody-transfer record", r.Outcome),
			"a transfer that did not happen does not end a chain; record the failure as the "+
				"operation that failed and let the chain continue")
	}
	// A transfer deploys nothing, and a second document reference beside
	// custody_transfer.final_artifact leaves the reader to guess which one is the
	// baseline being handed over.
	if r.Artifact != nil {
		p.add(path+".artifact", "is present on a custody-transfer record",
			"a transfer enforces nothing; the baseline being handed over is "+
				"custody_transfer.final_artifact")
	}
	if r.Enforcement != nil && !r.Enforcement.empty() {
		p.add(path+".enforcement", "is present on a custody-transfer record",
			"a transfer deploys nothing")
	}
	if r.EnvProfile != nil {
		p.add(path+".environment_profile", "is present on a custody-transfer record",
			"a transfer runs under no environment profile; the artifact in force is "+
				"custody_transfer.final_artifact")
	}
}

func (t *Target) validate(path string, p *problems) {
	if t == nil {
		return
	}
	if t.AccountID != "" && !reAccountID.MatchString(t.AccountID) {
		p.add(path+".account_id", fmt.Sprintf("%s is not a 12-digit AWS account id", safe(t.AccountID)),
			"use the id CreateAccount returned")
	}
	if t.OUID != "" && !reOUID.MatchString(t.OUID) {
		p.add(path+".ou_id", fmt.Sprintf("%s is not an OU or root id", safe(t.OUID)),
			"OU ids look like ou-abc1-12345678 and roots like r-abc1")
	}
	if t.Region != "" && !reRegion.MatchString(t.Region) {
		p.add(path+".region", fmt.Sprintf("%s is not a region", safe(t.Region)),
			"use the us-east-1 form")
	}
	if t.AccountName != "" && (!reProse.MatchString(t.AccountName) || len(t.AccountName) > maxProse) {
		p.add(path+".account_name", fmt.Sprintf("%s is not printable single-line text", safe(t.AccountName)),
			"an account name reaches reports a privileged reader acts on; a newline in one forges a line")
	}
}

func (d *DocRef) validate(path string, p *problems) {
	if d == nil {
		return
	}
	if !reDocID.MatchString(d.ID) {
		p.add(path+".id", fmt.Sprintf("%s is not a document id", safe(d.ID)),
			"use the lowercase-and-hyphens form catalogs and profiles use, e.g. cmmc-l1")
	}
	if !reSHA256.MatchString(d.ContentSHA256) {
		p.add(path+".content_sha256", fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(d.ContentSHA256)),
			"the hash is what makes the reference checkable rather than a label; a record naming "+
				"only an id has a subject that can be edited afterwards")
	}
	if d.SchemaVersion != "" && !reSemver.MatchString(d.SchemaVersion) {
		p.add(path+".schema_version", fmt.Sprintf("%s is not plain semver", safe(d.SchemaVersion)), "")
	}
}

func (pr *EnvProfileRef) validate(path string, p *problems) {
	if pr == nil {
		return
	}
	(&DocRef{ID: pr.ID, ContentSHA256: pr.ContentSHA256, SchemaVersion: pr.SchemaVersion}).validate(path, p)
	if pr.ReviewBy != "" && !reDate.MatchString(pr.ReviewBy) {
		p.add(path+".review_by", fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(pr.ReviewBy)),
			"a review date is a policy fact, not an event time; copy the environment profile's own value verbatim")
	}
	if len(pr.VerifiedSignatures) > maxVerifiedSignatures {
		p.add(path+".verified_signatures", fmt.Sprintf("has %d entries; the schema permits %d",
			len(pr.VerifiedSignatures), maxVerifiedSignatures), "")
	}
	seen := map[VerifiedSignature]bool{}
	for i, vs := range pr.VerifiedSignatures {
		vp := fmt.Sprintf("%s.verified_signatures[%d]", path, i)
		if !knownRole(vs.Role) {
			p.add(vp+".role", fmt.Sprintf("%s is not one of the attestation roles", safe(string(vs.Role))),
				"the vocabulary is closed at "+joinRoles()+": none of them means approved, "+
					"certified, or compliant, and the value of the set is that the weakest claim "+
					"cannot be read as the strongest")
		}
		if vs.Identity == "" || !reProse.MatchString(vs.Identity) || len(vs.Identity) > maxProse {
			p.add(vp+".identity", fmt.Sprintf("%s is empty or not printable single-line text",
				safe(vs.Identity)), "this list is rendered into reports; a newline in an identity "+
				"forges a line of one")
		}
		if vs.VerifiedAgainst != "" &&
			(!reProse.MatchString(vs.VerifiedAgainst) || len(vs.VerifiedAgainst) > maxProse) {
			p.add(vp+".verified_against", "is not printable single-line text", "")
		}
		if seen[vs] {
			p.add(vp, "duplicates an earlier entry",
				"an identity attesting twice in the same capacity is one attestation")
		}
		seen[vs] = true
	}
}

func (e *Enforcement) validate(path string, p *problems) {
	if e == nil {
		return
	}
	for i, r := range e.RegionSet {
		if !reRegion.MatchString(r) {
			p.add(fmt.Sprintf("%s.region_set[%d]", path, i),
				fmt.Sprintf("%s is not a region", safe(r)), "use the us-east-1 form")
		}
	}
	for i, s := range e.ServiceSet {
		if !reService.MatchString(s) {
			p.add(fmt.Sprintf("%s.service_set[%d]", path, i),
				fmt.Sprintf("%s is not a service namespace", safe(s)),
				"use the IAM service prefix, e.g. organizations")
		}
	}
	// Every one of these is a set in the schema (uniqueItems) and none of them admits
	// an empty member. Checked here because Append canonicalizes — sorting and
	// deduping — but a manifest read off disk went through no such thing, and an
	// enforcement list is the part of a record an auditor counts. "Three SCPs
	// attached" and "two SCPs, one listed twice" are different claims.
	for _, f := range []struct {
		name string
		vals []string
	}{
		{"scp_arns", e.SCPARNs},
		{"config_rule_names", e.ConfigRuleNames},
		{"region_set", e.RegionSet},
		{"service_set", e.ServiceSet},
		{"attestation_ids", e.AttestationIDs},
	} {
		seen := map[string]bool{}
		for i, v := range f.vals {
			at := fmt.Sprintf("%s.%s[%d]", path, f.name, i)
			if v == "" {
				p.add(at, "is empty", "an unnamed member of an enforcement set records nothing")
			}
			if seen[v] {
				p.add(at, fmt.Sprintf("%s duplicates an earlier member", safe(v)),
					"this is a set: a repeated member makes the list read as more enforcement "+
						"than was applied")
			}
			seen[v] = true
		}
	}
}

func (re *RecordError) validate(path string, p *problems) {
	if re == nil {
		return
	}
	if re.Message == "" {
		p.add(path+".message", "is empty",
			"an error record with no message records that something went wrong and withholds what")
	}
	for _, f := range []struct {
		name, val string
	}{
		{"message", re.Message},
		{"action", re.Action},
		{"resource", re.Resource},
		{"remediation", re.Remediation},
	} {
		if f.val != "" && !reProse.MatchString(f.val) {
			p.add(path+"."+f.name, "contains a control character",
				"these fields are printed back in reports, and a newline in one forges a line")
		}
	}
}

func (c *Custody) validate(path string, p *problems) {
	if c == nil {
		return
	}
	for _, f := range []struct {
		name, val, fix string
	}{
		{"transferee", c.Transferee,
			"name who holds the chain from the effective date onward; a chain ending with no " +
				"stated recipient is not meaningfully different from one that just stops"},
		{"reason", c.Reason,
			"say why the chain ends here; a chain that stops without a reason is " +
				"indistinguishable from one that was truncated"},
	} {
		if f.val == "" || !reProse.MatchString(f.val) || len(f.val) > maxProse {
			p.add(path+"."+f.name, fmt.Sprintf("%s is empty or not printable single-line text",
				safe(f.val)), f.fix)
		}
	}
	if !reDate.MatchString(c.EffectiveDate) {
		p.add(path+".effective_date", fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(c.EffectiveDate)),
			"custody passing is a policy fact usually agreed before or recorded after the moment it "+
				"takes effect, so it is a date and not this record's timestamp")
	}
	c.FinalArtifact.validate(path+".final_artifact", p)
	if c.SuccessorManifestID != "" && !reRoundTripID.MatchString(c.SuccessorManifestID) {
		p.add(path+".successor_manifest_id",
			fmt.Sprintf("%s is not a usable manifest id", safe(c.SuccessorManifestID)),
			"use letters, digits, dot, dash, and underscore: this is the pointer a successor "+
				"auditor follows years from now holding nothing but this record, so it has to be "+
				"a thing they can type — or omit it, since a transfer out of automat's scope has "+
				"no successor manifest and inventing one is a false claim of continuity")
	}
}

func (s *Signature) validate(path string, p *problems) {
	if s == nil {
		return
	}
	if !knownAlgorithm(Algorithm(s.Algorithm)) {
		p.add(path+".algorithm", fmt.Sprintf("%s is not a signing algorithm", safe(s.Algorithm)),
			"the set is closed at "+joinAlgorithms())
	}
	if s.KeyID == "" || !reRoundTripRef.MatchString(s.KeyID) {
		p.add(path+".key_id", fmt.Sprintf("%s is empty or not a usable key reference", safe(s.KeyID)),
			"a signature nobody can locate a key for is unverifiable in a way that looks verifiable; "+
				"a key id may be an ARN, so colons and slashes are fine, but a key-id mismatch is "+
				"refused with remediation text telling the operator to supply the key the record "+
				"names — a value they cannot retype makes that instruction useless")
	}
	if !reBase64.MatchString(s.Value) {
		p.add(path+".value", "is not base64",
			"encode the raw signature bytes with standard base64")
	}
}

// validateChain enforces the invariants over the sequence of records — the ones
// JSON Schema cannot express at all.
//
// Three of them:
//
//  1. Sequence numbers are 0..n-1 in order. The schema constrains each number in
//     isolation, so it accepts a chain whose records are numbered 0, 0, 7.
//  2. The links hold: records[0].previous_sha256 is 64 zeros, and every later
//     record's link is its predecessor's record_sha256. This is the chain.
//  3. A custody-transfer record is LAST. The schema can say "at most one" and
//     cannot say "last", because JSON Schema cannot refer to an array's final
//     position — so this is the half that lives here, pinned from the other side
//     by artifact.TestTheSchemaCannotSayCustodyTransferIsLast.
//
// Not enforced: that timestamps increase. See the package comment — an NTP
// correction between two vends is not tampering, and refusing the manifest would
// make it unreadable for a reason unrelated to its integrity.
func (m *Manifest) validateChain(p *problems) {
	for i := range m.Records {
		r := &m.Records[i]
		path := fmt.Sprintf("records[%d]", i)
		if r.Sequence != i {
			p.add(path+".sequence", fmt.Sprintf("is %d but the record is at position %d", r.Sequence, i),
				"sequence numbers run 0..n-1 with no gaps: a gap is either a dropped record or a "+
					"renumbered one, and neither is something a reader should have to guess about")
		}
		switch i {
		case 0:
			if r.PreviousSHA != ZeroHash {
				p.add(path+".previous_sha256", fmt.Sprintf("is %s on the first record", safe(r.PreviousSHA)),
					"the first record links to nothing and says so with 64 zeros; any other value "+
						"claims a predecessor this manifest does not contain")
			}
		default:
			if want := m.Records[i-1].RecordSHA; r.PreviousSHA != want {
				p.add(path+".previous_sha256", fmt.Sprintf("is %s but records[%d].record_sha256 is %s",
					safe(r.PreviousSHA), i-1, safe(want)),
					"the chain is broken here: either a record was edited, or one was removed from "+
						"between these two")
			}
		}
		if r.IsCustodyTransfer() && i != len(m.Records)-1 {
			p.add(path, fmt.Sprintf("is a custody-transfer record with %d record(s) after it",
				len(m.Records)-1-i),
				"custody passes out of automat's hands once and the chain ends there; a record "+
					"after a transfer means either the transfer was false or the chain was "+
					"reopened after it closed. JSON Schema cannot state this, which is why it is "+
					"checked here")
		}
	}
}

// validateHeaderAgainstRecords binds the manifest header to the chain it heads.
//
// # Why this exists (AUDIT-2 H4)
//
// CanonicalRecordJSON hashes a Record. It does not hash Meta, and nothing else did
// either — so the header was outside every record_sha256 and therefore outside every
// signature. Three consequences, all reproduced:
//
//  1. A manifest could be RELABELLED to any account and any organization without
//     disturbing a single hash. The records still named the original account in
//     operator.account_id and target.account_id; the header said otherwise; the file
//     verified. An auditor reading the header reads the wrong account.
//  2. A SIGNED record transplanted from one manifest into another verified unchanged,
//     because the bytes it was signed over never named the account.
//  3. A freshly built, never-tampered manifest whose header and records disagreed was
//     valid — so the defect was reachable by an ordinary bug, not only by an attacker.
//
// Covering Meta in the record hash was the other candidate fix and is the wrong one:
// it would make every record's hash depend on the header, so correcting a typo in
// meta.created_at would invalidate the whole chain and every signature on it. The
// header is not evidence; it is a label ON evidence. The right property is not "the
// label is signed" but "the label cannot disagree with what is signed" — which is
// checkable from the records themselves, on every read, at no cost to the chain.
//
// # What is compared, and what deliberately is not
//
// target.account_id, against meta.account_id, on every record that has a target. The
// target is what the operation acted ON, so it is the field that says which account
// the record is evidence about, and meta.account_id claims the same thing for the
// whole file.
//
// operator.account_id is NOT compared, and the reason is worth stating because the
// comparison looks obviously right. The operator is the principal that performed the
// operation — in every state automat runs in, the MANAGEMENT account, not the vended
// one (cmd/automat/vend.go passes caller.AccountID). A check comparing it to
// meta.account_id would fire on every correct manifest automat has ever written. That
// it reads as the natural thing to compare is exactly why it is named here rather
// than left out silently.
//
// Nothing is compared against meta.organization_id: no record field carries an
// organization id, so there is nothing in the chain to bind it to. That is a real
// residual — the org id in the header remains freely rewritable — and it is recorded
// in the audit rather than papered over with a check that cannot be written.
//
// created_at is compared as a lower bound on records[0].timestamp, and this check is
// NOT a genesis anchor. Saying precisely what it is worth matters more than the check
// does, because a weak check described as a strong one is worse than no check:
//
//   - It does NOT catch head truncation on its own. After a head truncation
//     created_at ≤ the dropped record ≤ the surviving record, so the bound is
//     satisfied by construction. Reproduced and confirmed during AUDIT-2.
//   - What it does catch is created_at rewritten FORWARD — relabelling a manifest as
//     newer than the operations in it, which is how a chain gets presented as evidence
//     about a period it does not cover.
//
// meta.genesis_sha256 IS a genesis anchor, added at AUDIT-2 H3's resolution, and it is
// what catches head truncation: it is records[0].record_sha256, set once by Append and
// compared here against whatever currently sits at records[0]. Dropping the front of a
// chain — records[0..k] — forces the new records[0] to carry PreviousSHA = ZeroHash to
// pass validateChain, which recomputes its record_sha256 to something other than what
// the header still anchors to. The check below is that comparison.
//
// This does NOT close truncation against a rewrite of the WHOLE file, header included.
// meta.genesis_sha256 sits outside every record_sha256 for the same reason created_at
// and account_id do — see the "Three consequences" above — so a rewriter who edits the
// header alongside the records changes the anchor along with what it anchors, and the
// document is internally consistent again. What genesis_sha256 converts head truncation
// into is DETECTABLE BY ANY HOLDER OF A SECOND COPY OF THE HEADER — an operator's local
// copy against the management-side mirror DESIGN 11 describes, or a birth certificate
// that recorded the value at vend time — rather than undetectable from the local copy
// alone. That is a real, bounded gain, and it is described that way rather than as
// "truncation closed": Q21 in docs/open-questions.md is the residual, a full-file
// rewrite, which needs a manifest-level attestation over canonicalized Meta and
// automat ships no trust anchor by design.
//
// The bound applies to records[0] only, because timestamps need not increase (see the
// package comment and
// TestTheSchemaAcceptsWhatGoAccepts/a_timestamp_that_steps_backwards): an NTP
// correction between two vends is not tampering, so a later record may legitimately
// predate an earlier one and therefore predate created_at.
//
// meta.id is NOT compared, even though vend sets it to the account id. Nothing in the
// schema or this package requires that, an operator may legitimately name a manifest
// something else, and a check that guesses at a convention is a check that fires on
// correct documents.
func (m *Manifest) validateHeaderAgainstRecords(p *problems) {
	if len(m.Records) > 0 && m.Meta.GenesisSHA != "" && m.Records[0].RecordSHA != "" &&
		m.Meta.GenesisSHA != m.Records[0].RecordSHA {
		p.add("manifest.genesis_sha256", fmt.Sprintf("is %s but records[0].record_sha256 is %s",
			safe(m.Meta.GenesisSHA), safe(m.Records[0].RecordSHA)),
			"the genesis anchor no longer matches the chain's first record. Either records were "+
				"removed from the front of this chain and the survivor's link was re-anchored to "+
				"ZeroHash — which recomputes its hash — or the header was edited by hand. Restore "+
				"the dropped records, or start a new manifest rather than editing this one's header")
	}

	for i := range m.Records {
		r := &m.Records[i]
		path := fmt.Sprintf("records[%d]", i)

		if got := targetAccount(r); m.Meta.AccountID != "" && got != "" && got != m.Meta.AccountID {
			p.add(path+".target.account_id", fmt.Sprintf("names account %s but the manifest header says "+
				"the manifest is about %s", safe(got), safe(m.Meta.AccountID)),
				"a manifest's header and its records must name the same account: the header is outside "+
					"every record hash and every signature, so a header that disagrees with the chain "+
					"is either a relabelled manifest or a record filed under the wrong account, and "+
					"both read to an auditor as evidence about an account they are not about")
		}
		if i == 0 && m.Meta.CreatedAt != "" && r.Timestamp != "" && r.Timestamp < m.Meta.CreatedAt {
			p.add(path+".timestamp", fmt.Sprintf("is %s, before the manifest's created_at of %s",
				safe(r.Timestamp), safe(m.Meta.CreatedAt)),
				"the first record cannot predate the manifest that contains it: the manifest is created "+
					"and its first record appended in the same run. created_at is outside every record "+
					"hash, so this is what notices it being moved FORWARD — a manifest relabelled as "+
					"newer than the operations it contains is a chain presented as evidence about a "+
					"period it does not cover")
		}
	}
}

// targetAccount is the target's account id, or "" if there is no target.
//
// Not a method on Target, because the nil case is the whole point: most records have
// no target and a nil dereference in a validator is a crash on the document it exists
// to reject.
func targetAccount(r *Record) string {
	if r.Target == nil {
		return ""
	}
	return r.Target.AccountID
}

func knownOperation(o Operation) bool {
	for _, v := range AllOperations {
		if v == o {
			return true
		}
	}
	return false
}

func knownOutcome(o Outcome) bool {
	for _, v := range AllOutcomes {
		if v == o {
			return true
		}
	}
	return false
}

func knownRole(r Role) bool {
	for _, v := range AllRoles {
		if v == r {
			return true
		}
	}
	return false
}

func knownAlgorithm(a Algorithm) bool {
	for _, v := range AllAlgorithms {
		if v == a {
			return true
		}
	}
	return false
}

func joinOperations() string {
	parts := make([]string, len(AllOperations))
	for i, o := range AllOperations {
		parts[i] = string(o)
	}
	return strings.Join(parts, ", ")
}

func joinRoles() string {
	parts := make([]string, len(AllRoles))
	for i, r := range AllRoles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}

func joinAlgorithms() string {
	parts := make([]string, len(AllAlgorithms))
	for i, a := range AllAlgorithms {
		parts[i] = string(a)
	}
	return strings.Join(parts, ", ")
}
