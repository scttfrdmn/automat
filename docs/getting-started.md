# Getting started

This walks all three states `automat preflight` can report, start to finish. If
you only need the standalone case in the fewest possible steps, README.md's own
quickstart covers it; this page goes one step further in each state and is the
one to read for the MEMBER case, which is DESIGN.md's primary motivating
scenario and is not in README.md at all.

Every command below is copy-pasteable and every flag name was checked against
`automat <command> --help` on the built binary — if this page and `--help`
ever disagree, `--help` is right and this page is stale.

## Which path is mine?

Sign in first — `automat login`, or export credentials any other way the
standard AWS credential chain resolves — then run:

```
automat preflight
```

It prints one of three states plus a capability report:

- **STANDALONE** — this account is in no organization. Go to
  [STANDALONE walkthrough](#standalone-walkthrough).
- **MANAGEMENT** — this account owns an organization already. Go to
  [MANAGEMENT walkthrough](#management-walkthrough).
- **MEMBER** — this account is in an organization it does not own. Go to
  [MEMBER walkthrough (the university case)](#member-walkthrough-the-university-case).

Read the certainty column preflight prints alongside each check. A permission
check here is evidence, not authorization: `iam:SimulatePrincipalPolicy` does
not evaluate service control policies, so a call reported as allowed from a
member account can still be denied by an SCP attached above it. A check
reliably tells you a grant is *missing*; it cannot promise a call will
succeed.

## STANDALONE walkthrough

This is a single AWS account with no organization yet, becoming the management
account of a brand-new one.

**1. Prepare the organization.** `--dry-run` first, since this is the one step
in the whole tool that AWS gives no call to undo — creating an organization is
permanent, so it needs `--yes`:

```
automat init --dry-run
automat init --yes
```

`init` creates the organization with `FeatureSet=ALL`, enables the service
control policy type on the root, and ensures an OU below it (named `Research`
by default; override with `--ou-name`). It prints the OU's id — you need it in
the next step.

**2. Write an environment profile.** This is the only file you author by
hand; everything else is discovered from AWS. See
[`docs/environment-profiles.md`](environment-profiles.md) for every field. A
minimal one:

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
  "account": {
    "email_pattern": "admin+{name}@example.edu"
  },
  "baseline": {
    "config_recorder": {
      "enabled": true,
      "delivery_bucket": "example-edu-automat-config"
    }
  }
}
```

Save it as `research-cui.json`. `placement.target_ou` is the OU id `init` just
printed — an `ou-xxxx-xxxxxxxx` value, not the OU's name. `delivery_bucket`
must already exist: `vend`'s in-child baseline work points the Config delivery
channel at it but does not create it.

**3. Vend an account.**

```
automat vend --environment-profile research-cui.json --name lab-alpha --dry-run
automat vend --environment-profile research-cui.json --name lab-alpha
```

No `--yes` needed — every step here is create-or-verify, and this is not the
one irreversible step `init`'s org-creation is. The command prints the new
account id, the birth certificate, and where it wrote the evidence manifest
(see [`docs/evidence-manifests.md`](evidence-manifests.md) for how to read
that file).

**4. Vend again, to see idempotency.**

```
automat vend --environment-profile research-cui.json --name lab-alpha
```

`vend` finds the existing account by its root email — which belongs to
exactly one AWS account — rather than creating a second one. The applied
report shows every step already satisfied; nothing new is created, moved, or
attached, and no new evidence record with a mutating outcome is appended
beyond an idempotent re-check. This is the property CLAUDE.md's rule 4
requires of every mutating command, and it is what makes `vend` safe to put on
a schedule or re-run after a partial failure without first checking whether
the account already exists.

**5. Verify it landed the way the profile says.**

```
automat verify --account <the-account-id-vend-just-printed> --environment-profile research-cui.json
```

A clean run reports every expected policy as `matches`, prints the freshness
and structural-honesty layers, and exits 0. `verify` is read-only: nothing it
does can change what is attached, no matter what it finds.

**6. What a drifted `verify` actually says.** Suppose someone detaches one of
automat's own service control policies from the OU through the AWS console.
The next `verify` run reads `internal/verify/policy.go`'s `PolicyReport` back
into the "Policy layer:" section of the report
(`cmd/automat/verify.go`'s `renderVerifyReport`), one line per policy the
current compile expects:

```
Account 444455556666 (OU/root "ou-abcd-11111111")

Policy layer:
  automat-research-cui-1: NOT ATTACHED
  automat-research-cui-2: matches

Freshness layer:
  environment profile is current (review_by 2027-06-30 has not passed)

Structural honesty:
  ...
  (detective and procedural findings are not checked in this build — see `automat verify --help`)

automat 0.1.0
```

A detached policy renders as `NOT ATTACHED`, never as a diff or a silent pass.
Three other renderings the same section can produce, from the same source:
`ATTACHED, content differs from a fresh compile` (someone edited the policy
document in place rather than removing it), `attached but not carrying
automat's owner tag (a name collision, not automat's drift)` (a different
policy happens to share the name automat would use — reported, not treated as
automat's own drift), and an `orphan (attached, automat's, no longer named by
this compile)` line for a policy automat once attached that a narrower profile
no longer names (nothing here can detach it — `verify` holds no write grant on
anything it inspects). `verify` exits 2 (`exitVerifyDrift`) whenever any
expected policy is not attached or does not match, or an orphan is found — the
exit code a cron job or CI step branches on. Exit 3 (`exitVerifyUnknown`) means
something else: nothing was found wrong, but a check could not complete (a
read was denied), so "clean" would overstate what was actually observed.

## MANAGEMENT walkthrough

This is the case where an organization already exists and this account
already owns it — created by hand in the console, by a different tool, or by
an earlier `automat init` run.

**Run `automat init` anyway.** It is not STANDALONE-only: `automat init`
permits both STANDALONE and MANAGEMENT, and refuses only MEMBER
(`cmd/automat/init.go`). Two reasons this matters here rather than being a
no-op:

- **A new organization has the service control policy type DISABLED on its
  root.** In that state `CreatePolicy` succeeds, `AttachPolicy` succeeds, and
  *nothing is enforced*. An organization someone stood up by hand in the
  console is very often in exactly this state, and `init` is what fixes it —
  refusing to run `init` here would send the operator who most needs it back
  to the console for the one call that decides whether anything automat later
  attaches actually enforces anything.
- **Every step is create-or-verify.** `init` reads the organization's current
  state before writing anything: if the policy type is already `ENABLED` it is
  left alone, and if the research OU already exists (by name) it is not
  recreated. Run `automat init --dry-run` first; against an already-prepared
  organization the plan reports nothing to do, and against one prepared by
  hand but with policies disabled, the plan shows exactly the one step
  (`EnablePolicyType`) that is missing.

`init` never attempts `CreateOrganization` in this state — that call happens
only for a caller preflight reports as STANDALONE — so no `--yes` is needed
here; `--yes` gates only the organization-creation step, and there is none to
gate when an organization already exists.

From here the rest of the flow is identical to the STANDALONE walkthrough:
write an environment profile, `vend`, `verify`. The only difference was
whether `init` had to create the organization or merely finish preparing one
that was already there.

## MEMBER walkthrough (the university case)

This is DESIGN.md's primary scenario: central IT holds the organization's
management account and will not run one-off account creation for a research
group. The research group runs automat from its own member account instead. Getting
straight which credentials are whose at each step matters more here than
anywhere else in this tool.

**1. `preflight` reports MEMBER with no vendor role.**

```
automat preflight
```

Run as the research group's own AWS identity, in the research group's own
account. The report shows state `MEMBER`, and (assuming nothing has been
configured yet) the vendor-role check comes back `Unknown` — there is no
`vendor_role_arn` configured to even attempt assuming. Nothing here is
brokered yet; every read so far was made with the research group's own
credentials.

**2. `automat setup --request` generates the onboarding bundle.**

```
automat setup --request --member-account 222233334444 --contact research-admin@example.edu --out automat-onboarding
```

Still the research group's own credentials, and this step makes **no AWS
call at all** — it only writes five files into `automat-onboarding/`
(`internal/bundle/write.go`):

- `README.md` — the cover note central IT reads. States what is being asked
  for, then a "Blast radius: what this cannot do" section explaining, in terms
  a security reviewer can act on, that the vendor role can only place accounts
  into the named OU, the delegation only touches policies on that OU
  (and only policies automat's own conventional tag marks as its own), and
  that any SCP central IT attaches *above* the OU still binds everything below
  — the delegate can restrict further, never loosen the institutional floor.
  It also names exactly what the delegation lets the research account *read*
  organization-wide (every account's root-user email, every SCP's full text)
  because that read cannot be scoped narrower and central IT should decide
  about it deliberately rather than discover it later.
- `delegation-policy.json` — the resource-based delegation policy statement:
  lets the research account create, update, tag, attach, and detach service
  control policies **it created itself**, on **the target OU subtree only**.
- `vendor-role.cfn.yaml` and `vendor-role.tf` — CloudFormation and Terraform
  for one IAM role in the *management* account (`automat-vendor` by default),
  trusting only the research account (or, better, one named role in it, via
  `--member-role-arn`) and requiring an `sts:ExternalId`. This role can create
  accounts and move them into the target OU subtree; it holds **no** policy
  permissions.
- `ou.md` — instructions for creating the target OU if it does not exist yet,
  and exactly which files and lines to edit once it does.

**3. What central IT does with it.** Central IT reads the bundle (it is
deliberately short — about a hundred lines per file), generates the
`ExternalId` themselves (`openssl rand -hex 24` — never accepted from the
requester, per the README), deploys the role via the CloudFormation template
or the Terraform, and applies the delegation policy — checking first whether
the organization already has a resource policy, since `PutResourcePolicy`
replaces it wholesale rather than merging. They then reply to the research
group with the role's ARN and, if it did not exist yet, the OU id. **The
`ExternalId` travels over a separate, out-of-band channel** — never in the
bundle, never in the same email as the role ARN.

Central IT can also apply the same grant directly, without the bundle, using
`automat setup` (no `--request`) run from the management account — the same
delegation and role creation, but performed by automat itself rather than
handed to central IT as files to review. This requires `--ou` (a real OU id)
and `--external-id-ref` naming where the `ExternalId` lives
(`env:VAR` or `file:/path`; automat does not generate one). The bundle path
exists for the case where central IT wants to review generated artifacts
before anything touches AWS; this path is for a central IT that is
comfortable running automat itself.

**4. Configure the research account and re-run `preflight`.** The research
group adds the role ARN, the `ExternalId` reference, the OU id, and an email
pattern to its own `~/.config/automat/config.toml` (`vendor_role_arn`,
`external_id_ref`, `ou`, `email_pattern` — see `docs/cli-surface.md`'s config
keys table), then:

```
automat preflight
```

Same account, same credentials as step 1 — nothing about *who* is running
this changed. What changed is that preflight now attempts
`sts:AssumeRole` against the configured vendor role ARN using the configured
`ExternalId`, and (once central IT's grant is live) reports it `Pass` with
certainty `Observed`: the assumption was actually attempted and succeeded, not
inferred.

**5. `vend` runs brokered.** From here, `vend` is the same command as the
STANDALONE and MANAGEMENT walkthroughs:

```
automat vend --environment-profile research-cui.json --name lab-alpha --dry-run
automat vend --environment-profile research-cui.json --name lab-alpha
```

What differs is invisible in the command line and load-bearing underneath it
(DESIGN §5): automat assumes the `automat-vendor` role in the *management*
account for `CreateAccount`, `DescribeCreateAccountStatus`, `MoveAccount`, and
`CreateOrganizationalUnit` — the create/move half, which AWS does not let a
member account do under its own identity at all. For the policy half —
creating, attaching, and detaching the OU's service control policies — automat
uses the research group's *own* (delegated) credentials, never the broker,
because that half AWS delegates natively via the resource-based delegation
policy and there is no reason to route it through an assumed role. Once the
account is created, automat assumes `OrganizationAccountAccessRole` *inside
the new child account* — a third, separate credential — to do the in-account
baseline work (Config recorder, conformance pack, automation role, opt-in
regions). Three different credentials, three different reasons, and no step
where the research group could accidentally act as central IT or vice versa.

## What's next

- [`docs/commands.md`](commands.md) — every command, every flag, exit codes,
  read-only/mutating/destructive, one example each.
- [`docs/environment-profiles.md`](environment-profiles.md) — every field in
  the document you just hand-authored above.
- [`docs/evidence-manifests.md`](evidence-manifests.md) — how to read the
  manifest `vend` just wrote, six months later, as a compliance reviewer would.
- [`docs/cli-surface.md`](cli-surface.md) — the flag-by-flag reconciliation
  against DESIGN.md §13, useful when something here and `--help` seem to
  disagree about *why*, not just *what*.
- [`docs/reclaim-design.md`](reclaim-design.md) and
  [`docs/assessment-reporting.md`](assessment-reporting.md) — what happens at
  the other two ends of an account's life, closing it and assessing it.
