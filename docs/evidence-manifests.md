# Reading an evidence manifest

Every mutating operation `vend` and `reclaim` perform, plus every `verify` and
`assess` run, appends a record to an account's evidence manifest
(`evidence-manifest/v1`, defined in `internal/evidence/types.go`). This page
is the reading guide for a compliance reviewer opening one of these files
months or years after the vend it describes — what the fields mean, what the
hash chain does and does not protect, and where to look for the two states
worth knowing about: parked and rotated.

The example excerpts below are `internal/evidence/testdata/golden/manifest.json`
verbatim, automat's own golden fixture — not an invented example.

## The birth certificate is not the manifest

`vend`'s final output includes a **birth certificate**: account id, OU,
control-artifact hash, enforcement summary, printed to the terminal
(`cmd/automat/vend.go`'s `renderBirthCertificate`). It is a *rendering* for the
operator running the command right now. The manifest is the durable record for
someone with neither the terminal output nor the memory of having run the
command. Nearly everything on the birth certificate also appears in the
manifest — the birth certificate exists anyway because a hash is what makes a
claim checkable, and printing it to the operator's own screen at the moment of
creation is a second, independent surface for the same claim the manifest
carries.

## The manifest's shape

```json
{
  "schema_version": "1.0.0",
  "manifest": {
    "id": "444455556666",
    "account_id": "444455556666",
    "organization_id": "o-abc1234567",
    "created_at": "2026-08-05T00:00:00Z",
    "genesis_sha256": "a36104635750bf3050360168f648583f0811e42e74e0775bf45144ee66abda74"
  },
  "records": [ /* ... */ ]
}
```

`manifest.id` is the manifest's own identity — for a per-account manifest,
the account id, so the file says which account it is about even found on its
own with no filename. `genesis_sha256` is `records[0]`'s own hash, copied into
the header once, at the first append, and never changed after. Its whole job
is to catch a specific attack: someone drops `records[0]` (the account-create
record — the one naming who created the account and under what credentials),
renumbers what remains, and re-anchors the new first record's `previous_sha256`
to the zero value. Every chain-internal check still passes; only a header that
still names the *original* first record's hash disagrees with what
`records[0]` now is. It does not catch a rewrite that touches the header too
— see "What the chain does and does not protect" below.

## One record

```json
{
  "sequence": 0,
  "timestamp": "2026-08-05T00:00:01Z",
  "operation": "account-create",
  "outcome": "success",
  "operator": {
    "arn": "arn:aws:sts::111122223333:assumed-role/automat-operator/session",
    "account_id": "111122223333",
    "user_id": "AROAEXAMPLEEXAMPLE:session",
    "assumed_role": "automat-operator"
  },
  "request_id": "req-abc123",
  "target": {
    "account_id": "444455556666",
    "account_name": "Physics CUI Enclave",
    "ou_id": "ou-abc1-12345678",
    "region": "us-east-1"
  },
  "artifact": {
    "id": "cmmc-l1",
    "content_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "schema_version": "1.0.0"
  },
  "environment_profile": {
    "id": "research-cui",
    "content_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
    "schema_version": "1.0.0",
    "review_by": "2026-11-10",
    "verified_signatures": []
  },
  "tool_version": "0.1.0",
  "previous_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "record_sha256": "a36104635750bf3050360168f648583f0811e42e74e0775bf45144ee66abda74",
  "signature": {
    "algorithm": "ed25519",
    "key_id": "test-key-1",
    "value": "NhED1NPymW9dMCA/HDbfMqBPe6yAl8Ige1HRpu0EzDewMB2ZVA5YpTdxenbt8Wm99HDnJq+yMf1xrc2NqZTKBA=="
  }
}
```

Field by field:

- **`sequence`** — position in the chain, from 0.
- **`operation`** — the closed vocabulary (`internal/evidence/types.go`'s
  `Operation`): `init`, `setup`, `account-create`, `account-move`,
  `ou-ensure`, `scp-ensure`, `baseline-apply`, `attestation-write`, `verify`,
  `assess`, `reclaim`, `custody-transfer`, `rotate`. The last two are
  **terminal** — nothing may follow either, and `IsTerminal()` is what
  `Append` and `verify`'s own chain check enforce that on.
- **`outcome`** — `success`, `failure`, or `parked`. Parked is not a kind of
  failure: it means real AWS state was left behind that a later `vend
  --resume` must find, and it is what `list` scans local manifests for.
- **`operator`** — the calling principal's ARN, account id, and (when
  assumed) the role name — never a bare "automat ran this."
- **`request_id`** — present on records tied to one `vend` invocation; this is
  the value `--resume <request-id>` takes.
- **`target`** — what the operation acted on: account id/name, OU id, region.
- **`artifact`** — the compiled control artifact by id, content hash, and
  schema version. This is what makes "these controls were attached" a
  checkable claim rather than a label — the hash is over the artifact's actual
  content, computed and verified independently by anyone holding the same
  catalog file.
- **`environment_profile`** — the profile that drove this vend, by id,
  content hash, schema version, and its own `review_by` (copied, so a reader
  years later can see the profile was already past review at vend time
  without needing the file). `verified_signatures` is **required, and an
  empty array is the normal v1 value** — no `omitempty` on this field,
  deliberately, because an absent field would read as "unknown" and the
  difference between "nothing was verified" and "the question was never
  asked" is exactly the one this record must not blur. automat verifies
  nothing in v1, so every manifest you will read today carries `[]` here; that
  is the honest answer, not a gap in the tool.
- **`enforcement`** (see the second record below) — what was actually
  attached or deployed: SCP ARNs, the conformance-pack ARN, Config rule
  names, the region and service sets, attestation ids.
- **`tool_version`** — the automat build that wrote this record.
- **`previous_sha256`** / **`record_sha256`** — the hash chain. The first
  record's `previous_sha256` is the distinguished zero value (64 zeros, not an
  empty string — an empty string would make "the first record" and "a record
  whose link was dropped" indistinguishable).
- **`signature`** — a detached signature over `record_sha256`, when a signing
  key is configured (`evidence_kms_key_id` in the config file, or a local
  key). Algorithm is `ed25519` today; two KMS forms are named in the schema so
  adopting one later is not a schema version event.

## The `baseline-apply` record's `enforcement` block

```json
"enforcement": {
  "scp_arns": [
    "arn:aws:organizations::111122223333:policy/o-abc1234567/service_control_policy/p-protect1",
    "arn:aws:organizations::111122223333:policy/o-abc1234567/service_control_policy/p-region2"
  ],
  "conformance_pack_arn": "arn:aws:config:us-east-1:444455556666:conformance-pack/automat-cmmc-l1/abcd1234",
  "config_rule_names": ["ACCESS_KEYS_ROTATED", "IAM_PASSWORD_POLICY"],
  "region_set": ["us-east-1", "us-west-2"],
  "service_set": ["config", "iam", "organizations"],
  "attestation_ids": ["MP.L1-b.1.vii"]
}
```

This is the "what actually happened" half, distinct from `artifact` (what the
compile *said* should happen). An empty `enforcement` block is omitted
entirely rather than rendered empty — canonicalization drops it, because an
empty block is noise a reader has to rule out and it would perturb the hash
for nothing.

## A parked record

```json
{
  "sequence": 2,
  "operation": "scp-ensure",
  "outcome": "parked",
  "request_id": "req-abc123",
  "target": { "account_id": "444455556666", "ou_id": "ou-abc1-12345678" },
  "error": {
    "message": "attaching the baseline-protection policy to ou-abc1-12345678 was denied",
    "action": "organizations:AttachPolicy",
    "resource": "arn:aws:organizations::111122223333:policy/o-abc1234567/service_control_policy/p-protect1",
    "remediation": "grant organizations:AttachPolicy on ou-abc1-12345678 to the delegated administrator role, then re-run: automat vend --resume req-abc123"
  }
}
```

**"Parked" means the account exists in AWS but the vend that created it did
not finish.** It is the state DESIGN §5 requires for exactly this reason: an
account created and left in the org root with no OU, no SCPs, and no manifest
pointer would be a real, billable AWS account nothing points at. Every parked
record carries an `error` block with the CLAUDE.md rule-7 shape — message,
action, resource, and remediation text naming the exact command to re-run.
`Manifest.Parked()` is how `automat list` finds these across every manifest
under `--evidence-dir`, most-recently-parked first; `automat vend --resume
<request-id>` is how you finish one.

## A custody-transfer record

```json
{
  "sequence": 3,
  "operation": "custody-transfer",
  "outcome": "success",
  "custody_transfer": {
    "transferee": "Research Computing, under the FY27 shared-services agreement",
    "effective_date": "2026-09-01",
    "reason": "The account moves to central IT operation; automat stops managing its baseline and this chain ends here.",
    "final_artifact": {
      "id": "cmmc-l1",
      "content_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "schema_version": "1.0.0"
    },
    "successor_manifest_id": "rc-central-444455556666"
  },
  "previous_sha256": "e0a78a2cd6ec50635eb9ee49d85454aa9e0bdaf4ca76a5ba081f717d14f94efa",
  "record_sha256": "3b7df7a5563517792683f2e19b0f2dafdcd03ea4ea79e6b2b05a2a66f6aaab06"
}
```

Custody passing to someone else — the account moves to central IT operation,
a grant is revoked, a project ends — closes the chain deliberately. This is
**terminal**: nothing may follow it, and its presence is what lets a reader
tell "this chain ended on purpose, here is who has it now" apart from "this
chain was truncated." `final_artifact` names what the account was actually
running under at handoff.

## Rotation, and when it happens

`RotateThresholdRecords` (`internal/evidence/store.go`) is **2,000 records** —
the point at which a manifest written to repeatedly (`verify` on a cron, a
heavily-resumed `vend`) should rotate to a fresh manifest via
`Manifest.Rotate`, well under the roughly 8,971-record ceiling
`MaxManifestBytes` (8 MiB) implies at about 935 bytes per record. Rotation is
meant to happen long before a manifest is at risk of refusing a write, not as
emergency surgery on one that already has. A `rotate` record is **also
terminal** and carries `RotationInfo` — `successor_manifest_id` (always
present; unlike a custody transfer, a rotation always produces a successor,
because producing one is the whole point), `reason`, and `record_count` (how
many records were in the closed manifest, including the terminal one itself).
It is a distinct type from `Custody` rather than `Custody` with empty fields,
because rotation has no answer to "who has custody now" — nobody's custody
changed, the file just filled up, and a rotate record carrying an empty
`transferee` would misread as a transfer to nobody.

## What the hash chain does and does not protect

Stated plainly, because overclaiming this is worse than the gap itself:

- **Detects:** an edit to any record except the last one — its own
  `previous_sha256`/`record_sha256` link breaks the chain forward from the
  edit.
- **Detects, via `genesis_sha256`:** truncation from the *head* (dropping
  `records[0]` and re-anchoring), as long as the manifest header travels
  unedited.
- **Does not detect, from the chain alone:** truncation from the *tail*
  performed consistently (drop the last N records, the file is now a shorter,
  internally valid chain) — this is why the terminal-record convention
  matters: a chain that does not end in a `custody-transfer` or `rotate`
  record but also isn't the live tail of an ongoing vend is worth asking
  about.
- **Does not detect, from the chain alone:** a rewrite that touches the
  header (`genesis_sha256` included) consistently with a tail truncation.
  What catches this is a second, independently held copy of the header —
  the evidence mirror, next.
- **Signatures narrow the residual** to someone who also holds the signing
  key — but `VerifyChain` does not flag a record whose signature is simply
  *absent* (a legitimate, mixed chain exists when a key is adopted partway
  through), so a rewriter can also delete the signatures they invalidated and
  the result verifies clean. `Manifest.SignatureCoverage` is how a reader asks
  the coverage question explicitly; nothing infers it for you.

## The evidence mirror

Optional: `baseline.evidence.in_account_bucket` and
`baseline.evidence.management_mirror_bucket` in the environment profile (see
[`docs/environment-profiles.md`](environment-profiles.md#evidence)) name S3
locations the manifest is additionally uploaded to, after the local write
succeeds. A local copy is always written regardless of whether a mirror is
configured (DESIGN §11).

The mirror is the compensating control for the truncation-plus-header-rewrite
gap above: two copies of the header that disagree are noticeable even when
neither copy is internally invalid on its own. `verify` checks this when at
least one mirror is configured — its "Evidence mirror layer:" section reports,
per configured bucket, whether the mirror `matches the local manifest`, is
`TRUNCATED relative to the local manifest`, `DISAGREES with the local
manifest`, or `could not verify` (unreachable). When no mirror is configured
at all, the section is omitted entirely rather than printed empty — "nothing
to check" and "checked, found nothing" are different claims, and omission is
how the former renders honestly.

## Further reading

- [`docs/environment-profiles.md`](environment-profiles.md) — the
  `baseline.evidence` fields that control where a manifest and its mirrors
  live, and the `review_by`/`signatures` fields a manifest's
  `environment_profile` reference points back at.
- [`docs/commands.md`](commands.md) — every command that writes or reads
  a manifest, and the `--evidence-dir` flag each one takes.
- [`docs/reclaim-design.md`](reclaim-design.md) — what a `reclaim` record
  looks like and why reclaim is durable-by-default rather than routine.
- DESIGN.md §11 and §11a — why the manifest exists, and the cosigning and
  freshness model behind `environment_profile.review_by` and
  `verified_signatures`.
