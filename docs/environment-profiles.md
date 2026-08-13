# Authoring an environment profile

The environment profile (`environment-profile/v1`) is the one file you write by
hand in this tool. Everything else — the control artifact, the region and
service sets it renders into SCPs, the evidence manifest — is compiled or
discovered. `vend` and `verify` both take one via `--environment-profile`.

This page walks every field the schema
(`schema/environment-profile-v1.schema.json`) and the Go type
(`internal/envprofile/types.go`) define, grouped the way both group them:
`environment_profile` (meta), `review_by`, `signatures`, `control_sets`,
`permitted`, `obligations`, `placement`, `account`, `baseline`. Two examples
follow at the end — a minimal profile carrying only the required fields, and a
fuller one exercising most of the optional ones. Both were loaded and
validated by the real binary's own validator (`envprofile.Load`), not merely
checked against the schema in isolation.

For what each field is *for* once `vend` runs — why controls are compiled by
union, why the permitted sets only ever narrow — see DESIGN.md §7a and §9.
This page is about what to write; DESIGN.md is about why the shape is what it
is.

## Top level

| Field | Required | Default | What it controls |
|---|---|---|---|
| `schema_version` | Yes | — | The schema major.minor.patch this document was written against. This build understands `1.x`; a different major is refused. |
| `environment_profile` | Yes | — | Identity: `id` and `title` (see below). |
| `review_by` | Yes | — | The date by which this profile must be re-read against the posture it deploys (see below). |
| `signatures` | No | — (empty) | Provenance attestations over this document's content hash. |
| `control_sets` | Yes | — | Which catalog ids to compile, by union, e.g. `["cmmc-l1"]`. |
| `permitted` | No | none — no additional boundary | The permitted-behavior boundary: region and service allowlists. |
| `obligations` | No | — (empty) | Obligation profiles this environment is built to satisfy, by id and hash. |
| `placement` | Yes | — | Where the account lands. |
| `account` | No | account-creation defaults apply | Account-creation settings. |
| `baseline` | Yes | — | The in-child work performed after account creation. |

## `environment_profile` (meta)

| Field | Required | Default | Controls |
|---|---|---|---|
| `id` | Yes | — | Stable identifier, 2–63 lowercase alphanumeric-and-hyphen characters. A **round-trip field**: written into account tags, SCP names, and evidence records, and an operator types it back. |
| `title` | Yes | — | Single-line human title, rendered into the birth certificate and reports. |
| `description` | No | — | Multi-line free text. |

## `review_by`

Required, `YYYY-MM-DD`, no default. This is the single field DESIGN §11a spends
a whole subsection justifying: a profile left alone keeps vending the posture
someone approved once, and every account it produces looks as current as the
day it was written. It sits inside the content hash, so extending the date is
itself a change no earlier attestation covers. `verify` **warns** — never
fails — once this date has passed; a lapsed review date is a statement about
the document's currency, not about the account's actual posture.

## `signatures`

Optional array (`maxItems: 16`), each entry a provenance attestation over this
document's content hash: `role` (one of `authored-by`, `adopted-by`,
`reviewed-by`, `interpreted-by`, `format-validated-by`), `identity`,
`statement` (required — the identity's own words, never a bare checkmark),
`content_sha256`, `attested_at`, and an optional `signature` block.

**A signature attests provenance and nothing else** — never correctness,
never applicability to a particular institution. automat ships no trust
anchor, loads no trust policy, and verifies nothing in v1
(`internal/envprofile/canonical.go`'s `VerifyAttestationSubjects` only checks
that each entry's `content_sha256` matches the document's own current hash —
not that the signer is trusted). If you add a `signatures` entry, its
`content_sha256` must equal the hash of the document *without* the
`signatures` array itself (excluded from the hash, along with `schema_version`
and `environment_profile`, per `HashExcludedFields` in
`internal/envprofile/canonical.go`) — attest the current content, not a value
you invent, or `Load` refuses the document.

## `control_sets`

Required, at least one member, each a catalog id (`cmmc-l1`, `800-171r2`,
`baseline-protection` is always included automatically and need not be
named). Compiled by union — DESIGN §9's meet-on-a-semilattice: union of
controls, intersection of permitted behavior.

## `permitted`

Optional object with `regions` and/or `services`, each an allowlist with
**`minItems: 1`** — an allowlist present but empty is refused outright, both
by the schema and by `internal/envprofile/validate.go`'s `checkAllowSet`,
because an empty allowlist is a deny-all that would be discovered only after
account creation and move had already succeeded (AUDIT-0's H5, the empty set
as the absorbing element of the meet).

Both fields **only ever narrow**: each is intersected with the corresponding
allowlist the compiled control sets already require, never substituted for it
and never added to it. An institution cannot widen its own posture by editing
an environment profile — the field is safe to expose here specifically
because of that direction.

`permitted` is **distinct from `baseline.regions`** (below). One is a
boundary — what a principal may call, enforced by an SCP the packer renders.
The other is an account-level action taken once, at baseline time, via the
Account Management API. An operator can legitimately enable a region without
permitting calls in it, or permit a region in policy that was never enabled.

`services` need not list the globally addressed namespaces (IAM, STS,
Organizations, Route 53, Support, billing, Health) — those are exempted from
the region Deny by the control artifact's own `region_deny_exempt_services`,
catalog data rather than something this document states.

## `obligations`

Optional array, `minItems: 1` when present, at most 8, each entry `{id,
content_sha256, revision_determination?}`. Names the obligation profiles
(`cmmc-l1`, `dfars-7012`, `nih-cadr-dua`) this environment is built to
satisfy — **recorded, not resolved**: automat does not decide that an
obligation applies. `revision_determination` (value, determined_by,
determined_at, statement — all required) is mandatory exactly when the
referenced obligation profile declares `revision_policy:
operator-determined`, and forbidden otherwise; that pairing is checked by
`CheckObligations` at vend time, not by the schema, since it depends on
reading the *other* document.

## `placement`

| Field | Required | Default | Controls |
|---|---|---|---|
| `target_ou` | Yes | — | Destination OU id (`ou-xxxx-xxxxxxxx` or a root id `r-xxxx`). New accounts always land under the root first and are then moved here (DESIGN §3 fact 4). |
| `create_intermediate_ous` | No | `false` | Permits creating OUs missing on `ou_path`, bounded by the five-level nesting limit. |
| `ou_path` | No | — (empty) | OU names to ensure beneath `target_ou`, outermost first, at most 5 entries. |

## `account`

Entirely optional; omit the whole block to take every default.

| Field | Required | Default | Controls |
|---|---|---|---|
| `email_pattern` | No | none — `--email` or config's pattern must supply one | Template for the account's root email; `{name}` is substituted with `--name`. Each account needs a globally unique email (DESIGN §3 fact 11). |
| `role_name` | No | `OrganizationAccountAccessRole` | The management-assumable role created in the child (DESIGN §3 fact 6). |
| `iam_user_access_to_billing` | No | `ALLOW` | Passed through to `CreateAccount`; `ALLOW` or `DENY`. |
| `tags` | No | — (empty) | Additional tags at creation. The `automat:` prefix is refused in both the key and the underlying SCP conditions that read it — an operator-writable key at the same scope a baseline-protection condition reads would be a forgeable one. |

## `baseline`

The in-child work performed after `vend` assumes into the account it just
created (DESIGN §7 step 5, implemented in full by `internal/baseline` — see
that package's doc comment for the ordering surprise: the automation role is
established *before* the OU's service control policies attach, reversing
DESIGN §7's own step numbering, because baseline-protection's IAM deny would
otherwise block the very call that permissions the automation role).

### `config_recorder` (required sub-object)

| Field | Required | Default | Controls |
|---|---|---|---|
| `enabled` | Yes | — | Whether the AWS Config recorder and delivery channel are established at all. |
| `all_supported_resources` | No | `true` | Recording scope: every supported resource type, or a narrower set (narrowing is not yet exposed by this field beyond the boolean). |
| `include_global_resource_types` | No | `true` | Whether global resource types (IAM, etc.) are included in the recording scope. |
| `delivery_bucket` | No | — | The S3 bucket the delivery channel writes to. **`EnsureConfigRecorder`/`EnsureDeliveryChannel` do not create this bucket** — it must already exist. Omitting it while `enabled: true` is a valid document that will fail at apply time when the delivery channel has nowhere to point. |

### `regions`

Optional. Opt-in region **enablement** via the Account Management API — a
one-time account action, not the permitted-region boundary (`permitted.regions`
above is that).

| Field | Required | Default | Controls |
|---|---|---|---|
| `home` | No | — | The account's home region. |
| `enable` | No | — (empty) | Regions to opt into. |
| `disable` | No | — (empty) | Regions to opt out of. |

### `automation_role`

Optional. The least-privilege in-account role automat creates for future
`verify` runs, and the one principal baseline-protection's SCPs exempt from
their own IAM-mutation Deny (DESIGN §10).

| Field | Required | Default | Controls |
|---|---|---|---|
| `name` | No | `automat-automation` | The role's name. |
| `create` | No | `true` | Whether to create it at all. |

### `disable_org_access_role_after_vend`

Optional boolean, default `false`. Whether to restrict further use of
`OrganizationAccountAccessRole` once baselining completes — see
`docs/disable-org-access-role-design.md` for the open design question around
the actual mechanism (a deny policy vs. narrowing who may assume it), which
DESIGN §7 does not itself settle.

### `attestations`

Optional. Where procedural-control attestation stubs are written.

| Field | Required | Default | Controls |
|---|---|---|---|
| `local_dir` | No | `compliance` | Local directory, relative to the working directory, contained (no `..`, no absolute path — the schema and the Go validator both refuse traversal, since this document may itself be attacker-controlled input received from someone else). |
| `in_account_bucket` | No | — | Optional in-account S3 mirror. |

### `evidence`

Optional. Where evidence manifests are written; a local copy is always
written regardless (DESIGN §11).

| Field | Required | Default | Controls |
|---|---|---|---|
| `local_dir` | No | `evidence` | Same containment rules as `attestations.local_dir`. |
| `in_account_bucket` | No | — | Optional in-account S3 mirror. |
| `management_mirror_bucket` | No | — | Optional management-account mirror. Meaningful only here — setting it under `attestations` is refused rather than silently ignored. |

## Example: minimal profile

Only the required fields. `baseline.config_recorder.enabled: false` is valid —
a profile may legitimately deploy no detective baseline, though a birth
certificate produced from one will say so.

```json
{
  "schema_version": "1.0.0",
  "environment_profile": {
    "id": "research-cui",
    "title": "Research CUI environment"
  },
  "review_by": "2027-06-30",
  "control_sets": ["cmmc-l1"],
  "placement": {
    "target_ou": "ou-abcd-11111111"
  },
  "baseline": {
    "config_recorder": {
      "enabled": false
    }
  }
}
```

## Example: fuller profile

Exercises `permitted`, `obligations`, `placement.ou_path`, `account`, and most
of `baseline`.

```json
{
  "schema_version": "1.0.0",
  "environment_profile": {
    "id": "research-cui",
    "title": "Research CUI environment",
    "description": "Physics group's CUI-rated enclave, vended under the FY27 delegation."
  },
  "review_by": "2027-06-30",
  "control_sets": ["cmmc-l1"],
  "permitted": {
    "regions": ["us-east-1", "us-west-2"],
    "services": ["ec2", "s3", "iam", "config", "organizations", "sts"]
  },
  "obligations": [
    {
      "id": "cmmc-l1",
      "content_sha256": "1111111111111111111111111111111111111111111111111111111111111111"
    }
  ],
  "placement": {
    "target_ou": "ou-abcd-11111111",
    "create_intermediate_ous": true,
    "ou_path": ["Physics"]
  },
  "account": {
    "email_pattern": "research-admin+{name}@example.edu",
    "role_name": "OrganizationAccountAccessRole",
    "iam_user_access_to_billing": "DENY",
    "tags": {
      "department": "physics",
      "cost-center": "12345"
    }
  },
  "baseline": {
    "config_recorder": {
      "enabled": true,
      "all_supported_resources": true,
      "include_global_resource_types": true,
      "delivery_bucket": "example-edu-automat-config"
    },
    "regions": {
      "home": "us-east-1",
      "enable": ["us-west-2"],
      "disable": []
    },
    "automation_role": {
      "name": "automat-automation",
      "create": true
    },
    "disable_org_access_role_after_vend": false,
    "attestations": {
      "local_dir": "compliance"
    },
    "evidence": {
      "local_dir": "evidence",
      "in_account_bucket": "example-edu-lab-alpha-evidence"
    }
  }
}
```

Note the `obligations[0].content_sha256` above (`1111...1111`) is a
placeholder for this example, not a real hash of any shipped `cmmc-l1`
obligation profile — in a real document, compute it from the actual file you
are referencing.

## Further reading

- [`docs/getting-started.md`](getting-started.md) — where this document fits
  in each of the three preflight-state walkthroughs.
- [`docs/commands.md`](commands.md) — `vend` and `verify`, the two commands
  that read this file.
- [`docs/evidence-manifests.md`](evidence-manifests.md) — how this profile's
  id, content hash, and `review_by` end up recorded in the evidence chain.
- [`docs/institutional-profiles.md`](institutional-profiles.md) — the
  classification-profile document type, a different one from this, naming an
  institution's own data levels.
- DESIGN.md §7a, §9, §10, §11a — the reasoning behind the union semantics,
  baseline-protection, and the cosigning/freshness model this document
  participates in.
