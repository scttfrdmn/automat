// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The evidence manifest has no Go implementation yet — Phase 2 writes the first
// record. These tests exercise the published schema directly, from raw JSON, for
// the reason the rest of this file's neighbours exist: schema/ is the contract,
// and a constraint nobody has fed a document to is a constraint nobody has
// checked. The custody-transfer rules in particular are expressed with
// not/contains/minContains and a three-way if/then/else, which are easy to write
// so that they accept everything.
//
// Deliberately no Go types: the Phase 1 review added custody-transfer as a
// forward-compatibility item explicitly without implementation, and inventing a
// Go struct here would be building the thing it said not to build.

func validateManifest(t *testing.T, sch *jsonschema.Schema, doc string) error {
	t.Helper()
	parsed, err := jsonschema.UnmarshalJSON(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("the test document is not JSON: %v\n\n%s", err, doc)
	}
	return sch.Validate(parsed)
}

// manifest wraps records in the surrounding document so each case below is just
// the records it is about.
func manifest(records ...string) string {
	return `{
  "schema_version": "1.0.0",
  "manifest": { "id": "111122223333", "account_id": "111122223333", "created_at": "2026-08-05T00:00:00Z" },
  "records": [` + strings.Join(records, ",") + `]
}`
}

const (
	zeroes = "0000000000000000000000000000000000000000000000000000000000000000"
	hashA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// vendRecord is an ordinary record: sequence 0, chaining to nothing.
const vendRecord = `{
  "sequence": 0,
  "timestamp": "2026-08-05T00:00:00Z",
  "operation": "baseline-apply",
  "operator": { "arn": "arn:aws:iam::111122223333:role/automat-operator" },
  "tool_version": "0.1.0",
  "previous_sha256": "` + zeroes + `",
  "record_sha256": "` + hashA + `"
}`

// transferRecord ends the chain.
const transferRecord = `{
  "sequence": 1,
  "timestamp": "2026-08-05T01:00:00Z",
  "operation": "custody-transfer",
  "operator": { "arn": "arn:aws:iam::111122223333:role/automat-operator" },
  "custody_transfer": {
    "transferee": "Research Computing, under the FY27 shared-services agreement",
    "effective_date": "2026-09-01",
    "reason": "The account moves to central IT operation; automat stops managing its baseline.",
    "final_artifact": { "id": "cmmc-l1", "content_sha256": "` + hashC + `", "schema_version": "1.0.0" }
  },
  "tool_version": "0.1.0",
  "previous_sha256": "` + hashA + `",
  "record_sha256": "` + hashB + `"
}`

// transferRecordWithoutPayload names the transfer operation and carries none of
// the detail that makes it one — the shape a chain would take if someone simply
// stopped writing records and labelled the last one.
const transferRecordWithoutPayload = `{
  "sequence": 1,
  "timestamp": "2026-08-05T01:00:00Z",
  "operation": "custody-transfer",
  "operator": { "arn": "arn:aws:iam::111122223333:role/automat-operator" },
  "tool_version": "0.1.0",
  "previous_sha256": "` + hashA + `",
  "record_sha256": "` + hashB + `"
}`

func TestACustodyTransferValidlyEndsAChain(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	// The point of the whole record type: a chain that stops here is a complete
	// document, not a truncated one.
	if err := validateManifest(t, sch, manifest(vendRecord, transferRecord)); err != nil {
		t.Errorf("a chain ending in a custody-transfer record must validate:\n%v", err)
	}

	// And a manifest that is nothing but a transfer — custody of an account
	// automat vended before manifests existed, handed on — is also valid. The
	// record type does not require a history to be terminal.
	only := strings.Replace(transferRecord, `"sequence": 1`, `"sequence": 0`, 1)
	only = strings.Replace(only, `"previous_sha256": "`+hashA+`"`, `"previous_sha256": "`+zeroes+`"`, 1)
	if err := validateManifest(t, sch, manifest(only)); err != nil {
		t.Errorf("a manifest consisting of one custody-transfer record must validate:\n%v", err)
	}
}

func TestACustodyTransferRecordMustCarryItsPayload(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	// Every case here is a way of ending a chain while saying less than the
	// terminal record is for. A chain may end once; it may not end vaguely.
	cases := []struct {
		name string
		doc  string
	}{
		{
			// Deliberately not "rename the key to something else": that form is
			// rejected by additionalProperties, so it would pass with the pairing
			// rule deleted and assert nothing about it. This drops the block.
			"no custody_transfer at all",
			transferRecordWithoutPayload,
		},
		{
			"no transferee",
			dropLine(t, transferRecord, `"transferee":`),
		},
		{
			"no effective_date",
			dropLine(t, transferRecord, `"effective_date":`),
		},
		{
			"no reason",
			dropLine(t, transferRecord, `"reason":`),
		},
		{
			"no final_artifact",
			dropLine(t, transferRecord, `"final_artifact":`),
		},
		{
			"final_artifact without a content hash",
			strings.Replace(transferRecord, `, "content_sha256": "`+hashC+`"`, "", 1),
		},
		{
			// A timestamp is an event time; an effective date is a policy fact.
			// Accepting a timestamp here would let the two be confused in the one
			// record whose whole job is to say when responsibility moved.
			"effective_date carrying a timestamp",
			strings.Replace(transferRecord, `"effective_date": "2026-09-01"`,
				`"effective_date": "2026-09-01T00:00:00Z"`, 1),
		},
		{
			// The reason is printed back in reports. A newline in it forges a line.
			"reason containing a newline",
			strings.Replace(transferRecord, `"reason": "The account moves`,
				`"reason": "Approved\n- account-move: 111122223333 -> r-root`, 1),
		},
		{
			"empty reason",
			strings.Replace(transferRecord,
				`"reason": "The account moves to central IT operation; automat stops managing its baseline."`,
				`"reason": ""`, 1),
		},
		{
			// A transfer that failed did not transfer anything, so it cannot be
			// what a chain ends on.
			"a failed transfer",
			strings.Replace(transferRecord, `"operation": "custody-transfer",`,
				`"operation": "custody-transfer", "outcome": "failure",`, 1),
		},
		{
			// artifact says "what this operation enforced"; a transfer enforces
			// nothing, and two artifact fields in one record leave a reader to
			// guess which is the baseline being handed over.
			"an artifact field alongside final_artifact",
			strings.Replace(transferRecord, `"tool_version": "0.1.0",`,
				`"artifact": { "id": "cmmc-l1", "content_sha256": "`+hashA+`" }, "tool_version": "0.1.0",`, 1),
		},
		{
			"an enforcement field claiming a deployment",
			strings.Replace(transferRecord, `"tool_version": "0.1.0",`,
				`"enforcement": { "conformance_pack_arn": "arn:aws:config:us-east-1:111122223333:conformance-pack/x" }, `+
					`"tool_version": "0.1.0",`, 1),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateManifest(t, sch, manifest(vendRecord, tc.doc)); err == nil {
				t.Errorf("the schema accepted a custody-transfer record with %s:\n%s", tc.name, tc.doc)
			}
		})
	}
}

func TestOnlyACustodyTransferRecordMayCarryACustodyTransfer(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	// The negative half of the pairing, and the one worth a test of its own: with
	// only the positive rule, a transfer could ride along on an ordinary
	// account-move record, where nothing reads for it and no rule forbids a
	// record following it. The chain would then have ended in a place no reader
	// looks.
	smuggled := strings.Replace(transferRecord, `"operation": "custody-transfer"`, `"operation": "account-move"`, 1)
	if err := validateManifest(t, sch, manifest(vendRecord, smuggled)); err == nil {
		t.Error("the schema accepted custody_transfer on an account-move record; " +
			"a transfer must be the operation, not a passenger on one")
	}
}

func TestAChainMayEndOnlyOnce(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	second := strings.Replace(transferRecord, `"sequence": 1`, `"sequence": 2`, 1)
	second = strings.Replace(second, `"previous_sha256": "`+hashA+`"`, `"previous_sha256": "`+hashB+`"`, 1)
	second = strings.Replace(second, `"record_sha256": "`+hashB+`"`, `"record_sha256": "`+hashC+`"`, 1)

	if err := validateManifest(t, sch, manifest(vendRecord, transferRecord, second)); err == nil {
		t.Error("the schema accepted two custody-transfer records in one chain; " +
			"custody can pass out of automat's hands once, and a second transfer means " +
			"either the first was false or the chain was reopened after it closed")
	}
}

// TestTheSchemaCannotSayCustodyTransferIsLast records a limit rather than
// asserting a behaviour, because a limit stated in a comment nobody runs is a
// limit that gets forgotten.
//
// JSON Schema cannot refer to an array's final position, so "nothing follows a
// custody-transfer record" is not expressible here. The schema enforces the half
// it can (at most one), and the chain validator Phase 2 writes must enforce the
// other half. If this test ever fails, the schema has become able to say it and
// the Go-side check can stop being the only thing standing there.
func TestTheSchemaCannotSayCustodyTransferIsLast(t *testing.T) {
	sch := compileSchema(t, "evidence-manifest-v1.schema.json")

	after := strings.Replace(vendRecord, `"sequence": 0`, `"sequence": 2`, 1)
	after = strings.Replace(after, `"previous_sha256": "`+zeroes+`"`, `"previous_sha256": "`+hashB+`"`, 1)
	after = strings.Replace(after, `"record_sha256": "`+hashA+`"`, `"record_sha256": "`+hashC+`"`, 1)

	if err := validateManifest(t, sch, manifest(vendRecord, transferRecord, after)); err != nil {
		t.Fatalf("this document is expected to pass the schema and be rejected by the chain "+
			"validator instead; if the schema now rejects it, delete this test and move the "+
			"constraint here:\n%v", err)
	}
	t.Log("recorded: the schema accepts a record after a custody-transfer record. " +
		"Enforcing terminality is Phase 2's chain validator, not the schema.")
}

// dropLine removes the one line containing marker, so a required-field case does
// not have to restate the whole document. It fails if marker is not present
// exactly once: a case that silently drops nothing asserts nothing.
func dropLine(t *testing.T, doc, marker string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	var out []string
	var hits int
	for _, l := range lines {
		if strings.Contains(l, marker) {
			hits++
			continue
		}
		out = append(out, l)
	}
	if hits != 1 {
		t.Fatalf("marker %q appears %d times in the document, want exactly 1", marker, hits)
	}
	// Removing a middle line can leave a trailing comma before the closing brace.
	joined := strings.Join(out, "\n")
	return strings.ReplaceAll(joined, ",\n  }", "\n  }")
}
