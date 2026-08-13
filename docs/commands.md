# Command reference

Every command `automat --help` lists, as of this writing: `login`, `preflight`,
`init`, `setup`, `vend`, `verify`, `list`, `assess`, `reclaim`, `version`, plus
cobra's own `help` and `completion`. Run `automat --help` yourself before
trusting this list — it is the one thing on this page most likely to have
changed since it was written.

Every flag, default, and exit code below was read from the built binary
(`automat <command> --help`) or from the command's own source in
`cmd/automat/`, not carried forward from DESIGN.md or from
[`docs/cli-surface.md`](cli-surface.md). Where this page and `--help`
disagree, `--help` is correct.

Two flags exist on every command and are omitted from each table below:
`--config <path>` (default `~/.config/automat/config.toml`) and `--context
<name>` (which named context in the config file to use).

## `automat login`

**What it does.** Runs the AWS SSO device authorization flow: prints a URL and
a code, waits for you to confirm them in a browser, and caches the resulting
token in `~/.aws/sso/cache` — the same place the AWS CLI and every AWS SDK
read it from. You do not need this command if credentials already reach
automat some other way (a shared-config profile, an instance or task role,
environment variables, an existing SSO session): every automat command reads
the standard AWS credential chain, and automat keeps no credential store of
its own.

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--start-url` | none | No — needed only for a fresh SSO session with no config-file `sso_start_url` |
| `--sso-region` | none | No, same condition |

**Exit codes.** Plain 0/1 — no taxonomy.

**Read-only / mutating / destructive.** Mutating in the narrow sense that it
writes a cached token to disk; makes no AWS write call.

**Example.**

```
automat login --start-url https://example.awsapps.com/start --sso-region us-east-1
```

## `automat preflight`

**What it does.** Classifies the caller's position in an organization —
`STANDALONE`, `MANAGEMENT`, or `MEMBER` (DESIGN §4) — and reports every
capability automat needs from here, with the exact grant that would fix
anything missing. It does not fail on a failed check: "MEMBER with no vendor
role configured yet" is preflight doing its job, not an error. See
[`docs/getting-started.md`](getting-started.md#which-path-is-mine) for what
each state means for what to run next.

**Flags.** None beyond the two global ones.

**Exit codes** (`cmd/automat/preflight.go`):

| Code | Meaning |
|---|---|
| 0 | Every check passed |
| 2 | At least one check failed — something is missing, and the report names the grant that fixes it |
| 3 | Nothing failed, but a check could not be completed — "ready" would overstate the evidence |

**Read-only / mutating / destructive.** Read-only.

**Example.**

```
automat preflight
```

## `automat init`

**What it does.** Prepares an organization to vend into: creates one with
`FeatureSet=ALL` if the caller's account is not in an organization yet,
enables the service control policy type on the root, and ensures an OU below
the root. Permits both `STANDALONE` and `MANAGEMENT` states and refuses
`MEMBER` — see [`docs/cli-surface.md`](cli-surface.md) D2 for why "STANDALONE
only" (DESIGN's original wording) does not survive contact with CLAUDE.md's
idempotency rule, and
[`docs/getting-started.md`](getting-started.md#management-walkthrough) for why
running it against an already-existing organization is not a no-op. Every step
is create-or-verify; running it twice writes nothing the second time.

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--ou-name` | `Research` | No |
| `--dry-run` | `false` | No — prints the plan and stops |
| `--yes` | `false` | Only when the plan includes creating a new organization — the one step in this command AWS provides no call to undo |

**Exit codes.** Plain 0/1.

**Read-only / mutating / destructive.** Mutating, and the one command outside
`reclaim` with a permanent, ungated step — creating an organization —
which is why `--yes` exists specifically for it and not for the rest of the
plan.

**Examples.**

```
automat init --dry-run
automat init --yes
```

## `automat setup`

**What it does.** Two unrelated modes selected by one flag.

With `--request` (the MEMBER-state path): generates the onboarding bundle a
member account sends to whoever runs the organization — delegation policy,
vendor role as both CloudFormation and Terraform, a cover note stating the
blast radius, and OU-creation instructions. Makes **no AWS call**; writes five
files. See
[`docs/getting-started.md`](getting-started.md#member-walkthrough-the-university-case)
for what each file says.

Without `--request` (the MANAGEMENT-state path): applies the delegation
policy and creates the vendor role directly, from the management account.
Ensure-semantics — a second run corrects drift rather than failing on
"already exists."

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--request` | `false` | Selects the bundle-generation mode |
| `--out` | `automat-onboarding` | No |
| `--contact` | none | No |
| `--dry-run` | `false` | No |
| `--force` | `false` | No — overwrites files that were hand-edited since generation |
| `--org` | config context's org | No, with `--request`; not applicable without it in the same way |
| `--ou` | none | No if `--ou-name` is given instead (OU not created yet); required in some form |
| `--ou-name` | none | Proposed name for an OU that does not exist yet |
| `--management-account` | none | The 12-digit management account |
| `--member-account` | none | The 12-digit requesting account |
| `--member-role-arn` | none | Narrows trust to one role rather than the whole member account (recommended) |
| `--vendor-role-name` | `automat-vendor` | No |
| `--external-id-ref` | none | **Required without `--request`**; ignored with it. `env:VAR` or `file:/path` — automat never generates an ExternalId |

**Exit codes.** Plain 0/1.

**Read-only / mutating / destructive.** With `--request`: writes local files
only, no AWS call. Without `--request`: mutating (creates an IAM role,
applies a resource-based delegation policy) but ensure-semantics, never
destructive.

**Examples.**

```
automat setup --request --member-account 222233334444 --contact research-admin@example.edu --out automat-onboarding
automat setup --ou ou-abcd-11111111 --external-id-ref env:AUTOMAT_EXTERNAL_ID --member-account 222233334444
```

## `automat vend`

**What it does.** Creates one AWS member account from an environment profile,
moves it into the target OU, ensures the OU's service control policies match
the compiled control sets, and — in this build — performs the full in-child
baseline: the automation role, opt-in region enablement, attestation stubs,
the Config recorder and delivery channel, and the conformance pack (DESIGN §7
step 5, in full, per `internal/baseline`). Controls attach before the account
is handed to anyone, and the evidence manifest is what lets "born compliant"
be a checkable claim rather than an assertion. Every step is create-or-verify;
a run that fails after the account exists **parks** rather than aborting, and
`--resume` continues it.

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--environment-profile` | none | **Required** |
| `--name` | none | No, but effectively needed to identify the account |
| `--email` | environment profile's or config's email pattern | No |
| `--ou` | environment profile's `placement.target_ou` | No — overrides it |
| `--resume` | none | No — a create-account request id from an earlier parked run |
| `--override` | none | No — resolves a Config-rule parameter conflict the union could not settle on its own (DESIGN §9) |
| `--dry-run` | `false` | No |

**Exit codes.** Plain 0/1 — no richer taxonomy than that; a parked run still
exits non-zero and is recorded, not silently swallowed.

**Read-only / mutating / destructive.** Mutating; not destructive (creates
and configures, never deletes or closes).

**Examples.**

```
automat vend --environment-profile research-cui.json --name lab-alpha --dry-run
automat vend --environment-profile research-cui.json --name lab-alpha
automat vend --environment-profile research-cui.json --resume car-abc123defg456
```

## `automat verify`

**What it does.** Re-checks one account against the environment profile that
vended it: the policy layer (do the attached service control policies still
match a fresh compile) and the freshness layer (has `review_by` passed). Also
renders the structural-honesty breakdown (per-control enforcement-class
counts) and, when a mirror bucket is configured, mirror-drift findings. The
detective and procedural layers are described in the command's own output as
not checked in this build. Read-only: the interface it uses to inspect an
account holds no write method.

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--account` | none | **Required** |
| `--environment-profile` | none | **Required** |
| `--override` | none | No — must match whatever `vend` used, or the recompiled expectation will not be the one actually attached |

**Exit codes** (`cmd/automat/verify.go`):

| Code | Meaning |
|---|---|
| 0 | Clean — every expected policy attached and matching, no orphans |
| 2 | Drift: an expected policy missing or changed, or an orphan found |
| 3 | Nothing found wrong, but a check could not be completed |

**Read-only / mutating / destructive.** Read-only.

**Example.**

```
automat verify --account 444455556666 --environment-profile research-cui.json
```

## `automat list`

**What it does.** Inventories the organizational units and accounts under a
root OU (or the organization root, if none is configured), plus every account
a local evidence manifest records as parked. Makes no write *call*, but is not
read-only by construction the way `verify` is: the tree walk travels the same
client `vend` uses (brokered through the vendor role in the MEMBER state),
which carries write methods `list` simply never calls. Tag-based filtering is
not available — the vendor role bundle grants no
`organizations:ListTagsForResource` on account resources, so every account
under the walked root is listed regardless of any `automat:*` tag.

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--ou` | config file's `ou`, or the organization root | No |
| `--evidence-dir` | `evidence` | No |

**Exit codes.** Plain 0/1.

**Read-only / mutating / destructive.** No write call made, but see above —
not read-only by the type system the way `verify` is.

**Example.**

```
automat list --ou ou-abcd-11111111 --evidence-dir evidence
```

## `automat assess`

**What it does.** Renders a canonical assessment-result document and a
human-facing CMMC Level 1 MET/NOT MET summary against the fifteen L1 practices
in `catalogs/cmmc-l1.json`. Every page is marked `DRAFT — NOT A SUBMISSION`
and carries the policy caveat (`docs/policy-caveat.md`): automat generates the
packet an affirming official reads, never the thing they sign. This build
contributes **zero machine evidence** for any of the fifteen practices — the
catalog carries no SCP fragments and no AWS Config read path exists — so every
practice renders NOT MET unless `--determinations` supplies an operator
determination for it. See [`docs/assessment-reporting.md`](assessment-reporting.md)
for the staged scope this command sits inside (only Stage 3 ships).

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--account` | none | **Required** |
| `--profile` | none | **Required** — only `cmmc-l1` accepted today |
| `--scope-statement` | none | **Required** — your own statement of what the account covers, never automat's inference |
| `--out` | none | **Required** |
| `--determinations` | none | No — omit to render every practice NOT MET |
| `--evidence-dir` | `evidence` | No — must match whatever `vend`/`verify` used for this account, since `assess` has no `--environment-profile` of its own to read `baseline.evidence.local_dir` from |

**Exit codes.** Plain 0/1.

**Read-only / mutating / destructive.** Read-only against AWS beyond one
`sts:GetCallerIdentity` call (for evidence attribution). Writes locally: the
assessment-result document, the rendered summary, and an `OpAssess` evidence
record.

**Example.**

```
automat assess --account 444455556666 --profile cmmc-l1 \
  --scope-statement "Physics CUI enclave, single-account boundary" \
  --out assess-out --determinations determinations.json
```

## `automat reclaim`

**What it does.** Detaches automat's own service control policies from the
account's OU placement, then calls `CloseAccount`. The one destructive command
in the tree: a vended account is durable by default, and applying this is a
rare, deliberate event rather than routine teardown. Only a policy carrying
automat's own owner tag is detached — an institution's own SCP at the same OU
is reported and left alone. AWS holds a closed account in `SUSPENDED` status
for a 90-day grace window, reinstatable only through AWS Support; after that
it cannot be reopened. There is no programmatic pre-check against AWS's
closure rate limit (the higher of 250 or 20% of member accounts per rolling 30
days, up to 1,000); a rejection is reported with that limit named. See
[`docs/reclaim-design.md`](reclaim-design.md) for the full design.

**Flags.**

| Flag | Default | Required |
|---|---|---|
| `--account` | none | **Required** |
| `--dry-run` | `false` | No |
| `--yes` | `false` | Required unconditionally to apply — no lighter-weight path, unlike `init`'s org-creation-only gate |
| `--evidence-dir` | `evidence` | No — same reasoning as `assess`'s: no `--environment-profile` to read a customized directory from |

**Exit codes.** Plain 0/1.

**Read-only / mutating / destructive.** Destructive. `--dry-run` prints the
plan and stops; the applying form requires `--yes` with no partial or
softer path.

**Examples.**

```
automat reclaim --account 444455556666 --dry-run
automat reclaim --account 444455556666 --yes
```

## `automat version`

**What it does.** Prints the version stamped into generated artifacts (the
same value that appears in every birth certificate and evidence record's
`tool_version` field).

**Flags.** None beyond the two global ones.

**Exit codes.** Plain 0/1.

**Read-only / mutating / destructive.** Read-only.

**Example.**

```
automat version
```

## Further reading

- [`docs/getting-started.md`](getting-started.md) — the walkthroughs these
  commands compose into, for all three preflight states.
- [`docs/environment-profiles.md`](environment-profiles.md) — the document
  `--environment-profile` points at.
- [`docs/evidence-manifests.md`](evidence-manifests.md) — what every mutating
  command above (plus `verify` and `assess`) writes into `--evidence-dir`.
- [`docs/cli-surface.md`](cli-surface.md) — the flag-by-flag reconciliation
  against DESIGN.md §13, with the reasoning behind several of the odder
  corners (why `verify` takes `--account` and not `--ou`, why `--override`
  exists, why `list` has no tag filter).
