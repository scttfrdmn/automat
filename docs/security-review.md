# The security review

For whoever at central IT is asked to approve the onboarding bundle `automat setup
--request` generates. The bundle's own `README.md` makes the blast-radius argument for the
requester to forward; this page is the standalone version, written for the person deciding
whether to approve it, and it is a companion to that README rather than a restatement of it
— read both.

**The grant is two documents: one delegation policy and one IAM role.** Nothing else
reaches your organization. Below is exactly what each grants, what it cannot do, and what
to check before applying either one.

## The delegation policy

Five statements, each scoped by a condition — none of them a blanket grant:

| Statement | Actions | Scoped by |
|---|---|---|
| Create | `CreatePolicy` | request tag `automat:managed-by=automat` |
| Modify | `UpdatePolicy`, `DeletePolicy` | resource tag `automat:managed-by=automat` already present |
| Tag | `TagResource`, `UntagResource` | resource tag already present, and only within the `automat:*` key namespace |
| Attach | `AttachPolicy`, `DetachPolicy` | resource tag already present, **and** the target is inside the delegated OU subtree |
| Read | `Describe*`/`List*` (organization, OU, policy, account) | none — org-wide reads, no write anywhere in this row |

**The one condition worth reading twice**: every modify/tag/attach action is gated on the
**resource** tag, never the **request** tag. A condition reading a tag the caller may
itself write constrains nothing — gating on the request tag would let the delegate stamp
`automat:managed-by=automat` onto a policy it did not create and then rewrite it, which is
exactly the escalation path a resource-tag gate closes. If you find a `RequestTag`
condition anywhere in the modify/tag/attach statements of the file you were sent, that is
not this policy — stop and ask.

**What this policy cannot do, structurally**: it cannot touch a policy central IT wrote
(no resource tag, no access), it cannot attach anywhere outside the named OU and its
descendants (the attach statement's resource list is the subtree, not `*`), and it cannot
close, suspend, or remove an account, move an account it did not create, or touch anything
inside a vended account — none of those actions appear in this policy at all.

**What it can do, easily read past**: it can detach a policy it attached. A tool that can
only ever add controls cannot correct a mistake, so `DetachPolicy` is granted — scoped to
resource-tagged, automat-owned policies only, the same gate every other write in this
statement uses. This is why a control automat attaches to a vended account is not
permanent against the account that vended it: re-run `automat verify` to confirm what is
actually attached rather than trusting a past run's report.

## The vendor role

One IAM role (`automat-vendor` by default), assumable only by the principal your requester
named, gated on an `sts:ExternalId` your side generates and transmits out of band — **no
secret ships inside the bundle**. `MaxSessionDuration` is one hour.

Six statements in its own inline policy:

| Statement | Grants | Scoped by |
|---|---|---|
| Create accounts | `CreateAccount` | request tags `automat:vended-by`/`automat:ou` must match this member account and OU |
| Move | `MoveAccount` | resource tag `automat:vended-by` on the account, destination confined to the delegated OU subtree |
| Create sub-OUs | `CreateOrganizationalUnit` | confined to the delegated OU subtree (no tag condition — a fresh OU has none yet) |
| Tag accounts | `TagResource` (accounts) | resource tag present, and only the mutable subset (`automat:artifact-id`, `automat:artifact-sha256`, `automat:version`) — `vended-by`/`ou` are set once at creation and never made re-writable |
| Tag OUs | `TagResource` (OUs) | mutable-key-only, same reasoning |
| Read | seven `Describe*`/`List*` calls | none |

**What this role cannot do today**: **close an account.** `organizations:CloseAccount`
does not appear in the role's policy. `automat reclaim` calls it through this same role in
a member account and will be denied until the role is widened — a known, disclosed gap
(`docs/reclaim-design.md`), not an oversight to catch in review. If a bundle you receive
grants `CloseAccount`, that is wider than this project's shipped templates; treat it as a
deliberate, separately-justified change, not the default.

Nor can this role delete an OU, remove an account from the organization, leave the
organization, delete the organization, deregister a delegated administrator, disable the
service-control-policy type org-wide, delete the organization's resource policy, or untag
anything through its own inline policy. None of those actions appear anywhere in the role.

## What to check, specifically

1. **Principal and Resource on every statement** — the delegation policy's `Principal`
   must be the requester's account or one named role, never `*`; every `Resource` must
   name the specific OU subtree, never the organization root.
2. **The two `TagResource` statements, read together** — one on the delegation policy
   (gated on the resource tag, the escalation-proof direction) and one on the role
   (gated on the mutable-key allowlist). Confirm neither has drifted onto the request tag
   or onto an unrestricted key list.
3. **The trust policy's `ExternalId`** — must be a template parameter (`!Ref` in
   CloudFormation, `var.` in Terraform), never a literal value baked into the file you
   received. A literal ExternalId defeats the confused-deputy defense it exists for.
4. **No `organizations:*Policy` action anywhere in the role** — policy operations run on
   the requester's own delegated identity in every state; a role that could also create or
   attach policies would let the two halves of this grant collapse into one, wider one.
5. **`MoveAccount`'s condition** — both the resource-tag gate and the destination-subtree
   scoping must be present together; either alone is a narrower guarantee than the pair.
6. **`CreateOrganizationalUnit`'s resource list** — confined to the subtree, so a
   compromised or buggy caller cannot create OUs anywhere else in your organization.

## The honest caveat

This document, and the bundle's own README, describe what the *grant* permits. Neither is
a substitute for reading the actual JSON/YAML/HCL you were sent — a template is text, and
text can be edited after generation. `docs/vs-control-tower.md`'s earlier claim that this
review is "around sixty lines" undercounted it: the delegation policy alone renders to
roughly 120 lines of JSON, and the role template to 180–200 lines including the trust
policy and inline comments — closer to three hundred lines across both files before the
cover note. That is still short enough to read in one sitting, which is the actual claim
worth making, rather than a specific number that drifts every time either template gains a
comment.
