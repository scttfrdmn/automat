# CLI surface vs. DESIGN §13

The Phase 1 review ratified the CLI surface AUDIT-1 listed **on the condition that it
matches DESIGN §13**, and asked that any deviation be flagged as its own line item, now
and in future audits. This page is that reconciliation. It is kept current per phase;
an audit that says "the surface matches §13" without this page behind it is a claim
outrunning its evidence.

Everything below was read from the built binary (`automat <cmd> --help`) and from
`internal/config`'s struct tags, not from the design document or from AUDIT-1's list.
That direction matters: checking §13 against a summary of the code would find nothing.

## Commands

§13 lists eleven command forms. Phase 1 ships three plus two cobra built-ins.

| §13 command | State | Where |
|---|---|---|
| `automat login` | **Shipped** | `cmd/automat/login.go` |
| `automat preflight` | **Shipped** | `cmd/automat/preflight.go` |
| `automat setup --request` | **Shipped** | `cmd/automat/setup.go` |
| `automat setup` (MANAGEMENT) | Not yet — Phase 3 | Refuses with the phase named |
| `automat init` | Not yet — Phase 2 | ROADMAP Phase 2 |
| `automat vend` | Not yet — Phase 2 | ROADMAP Phase 2 |
| `automat compile` | Not yet — see below | `gen/catalog` today |
| `automat verify` | Not yet — Phase 4 | ROADMAP Phase 4 |
| `automat list` | Not yet — Phase 4 | ROADMAP Phase 4 |
| `automat reclaim` | Not yet — Phase 5 | ROADMAP Phase 5, `LATER` in §13 |

Also present and not in §13: `version`, `help`, `completion`. `version` is a
deliberate addition (a tool that stamps its version into generated artifacts must be
able to state it); `help` and `completion` are cobra's, registered automatically.
None takes a flag with security meaning.

**No command in §13 is missing for a reason other than not being built yet, and no
shipped command is absent from §13.**

## Flags

| Scope | Flags | In §13? |
|---|---|---|
| Persistent | `--config`, `--context` | Implied by §13's config paragraph |
| `login` | `--start-url`, `--sso-region` | Implied by "credential-profile-aware" / SSO |
| `preflight` | none | — |
| `setup` | `--request`, `--dry-run`, `--force`, `--out`, `--org`, `--ou`, `--ou-name`, `--management-account`, `--member-account`, `--member-role-arn`, `--vendor-role-name`, `--contact` | §13 names none of these |

§13 specifies commands, not flags, so a flag cannot contradict it by existing. The two
with security semantics remain the ones AUDIT-1 flagged: `--force` (discards a hand
edit — the mechanism an operator uses to apply a correction central IT asked for) and
`--out` (a path, hence the control-byte refusal and the `os.Root` work in
`internal/bundle/write.go`).

### One flag was removed since AUDIT-1: `--external-id`

AUDIT-1's ratified list included `setup --external-id`. It is gone, as part of
inverting ExternalId generation (Phase 1 review item 6). **This is not a §13
deviation, in either direction:**

- §13's command list does not mention it, so removing it cannot diverge from the list.
- §13's config paragraph says *"Never store secrets; lean on the AWS credential chain
  and OS keychain if anything must persist."* The flag existed to put a secret into a
  generated file. Removing it moves the code toward that sentence, not away from it.

Recorded here rather than left as a silent shrinkage of a ratified surface: the review
ratified a list that has since changed, and the change should be visible without
diffing two audits.

## Config keys

§13 names four per-org context keys. All four exist, with these TOML names
(`internal/config/config.go`):

| §13 | Key |
|---|---|
| vendor role ARN | `vendor_role_arn` |
| ExternalId ref | `external_id_ref` |
| OU id | `ou` |
| email pattern | `email_pattern` |

Plus `org`, `region`, `profile`, `sso_start_url`, `sso_region`, and the top-level
`context` / `default_context`. Additions, not substitutions — `region` and `profile`
are what "credential-profile-aware" in §13's `login` line requires, and the two `sso_*`
keys are what let `login` work without re-typing a start URL.

**`profile` here is the AWS credential profile and nothing else.** It is the fourth
sense of the word DESIGN §7a enumerates, and the one that cannot be renamed because it
is AWS-standard in every other tool the operator uses. `vend`'s input document is the
**environment profile**, reached by `--environment-profile`; the two must never share a
flag name. §13 line 100 originally spelled the vend input `--profile`, which would have
put both meanings on one flag in one tool — DESIGN §7a now resolves that, and this row
is the CLI-side half of the same fix.

**§13's "never store secrets" holds literally.** `external_id_ref` stores a *reference*
(`env:VAR`, `file:/path`), resolved at assume time by `config.ResolveExternalID` and
never written back. No config key holds a credential. This is asserted, not just
intended: `TestPreflightNeverPrintsTheExternalID` covers the CLI's output paths.

## Deviations

One, found by writing this page.

### D1 — The CLI named the wrong phase for `setup` without `--request`. FIXED

`automat setup` in a management account is not implemented, and the error told the
operator it "arrives in Phase 2". ROADMAP.md schedules it in **Phase 3**: *"`setup`
(MANAGEMENT side): apply delegation policy + create vendor role for a named member
account."* Phase 2 is `init` and `vend`.

Not a cosmetic slip. That string is a promise made to an operator who is blocked, in
the one place they will look — and it named a release that will not contain what they
are waiting for. It appeared in three operator-facing spots (the `Long` help, the
refusal message, the command's doc comment) plus `docs/phase-1.md`, all fixed, with
the test now asserting the phase *number* rather than the word "Phase" so the next
drift fails loudly. CLAUDE.md's rule — when design and code disagree, flag it rather
than reinterpret — puts ROADMAP as the sequencing authority, so the code was wrong.

### Not a deviation: `automat compile` lives in `gen/catalog`

§13 lists `automat compile`, and ROADMAP Phase 0's accept criterion writes it as
`automat compile --sets cmmc-l1 --out a.json`. What exists is `gen/catalog`, a separate
maintainer-time binary with `-out`, `-sources`, and `-check`.

Called out because it looks like a deviation and is not, yet: Phase 0 is about the
compiled artifact being a versioned contract, and the compiler that produces the
vendored catalogs is maintainer tooling by design — `gen/catalog/doc.go` states that
it is "the only thing that ever reads an upstream catalog format", running at
maintainer time while automat itself reads only the compiled output. Whether `compile`
also needs to be an operator-facing subcommand is a real question (an operator
composing their own control set from vendored catalogs would want it, and §9's union
semantics are the reason to expect that), but it is not answerable in Phase 1 and
nothing in Phase 1 needs it.

**Carried to AUDIT-2 as an open item:** either `automat compile` ships as a subcommand
over `internal/compilesets`, or §13's list is amended to say the compiler is
maintainer tooling. Leaving a command in the design's CLI list with no plan to build
it is how a design document stops being the source of truth.
