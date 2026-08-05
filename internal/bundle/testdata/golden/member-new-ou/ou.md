# The target organizational unit

This bundle needs an OU that does not exist yet. **Create it first**, then replace
the placeholder in the other files. Three steps.

## 1. Create the OU

From the management account (111111111111). The proposed name is "Research Computing"; use whatever
your naming convention requires — automat does not care about the name, only the id.

```
aws organizations list-roots --query 'Roots[0].Id' --output text
aws organizations create-organizational-unit \
  --parent-id <the root id, or a parent OU id> \
  --name "Research Computing"
```

The OU may sit anywhere in your hierarchy. Under a parent OU is often the right
place: service control policies you attach to that parent still bind everything
inside this one, so nesting it is how you keep it under an existing baseline
rather than beside it.

Note the returned `Id` — the `ou-xxxx-xxxxxxxx` form. That is the only value needed below.

## 2. Replace the placeholder

Every generated file contains the literal string:

```
ou-REPLACE-WITH-THE-NEW-OU-ID
```

Replace all occurrences with the real OU id, in these files:

| File | Occurrences are in |
|---|---|
| `delegation-policy.json` | the `Resource` arrays |
| `vendor-role.cfn.yaml` | the `MoveAccount` and `CreateOrganizationalUnit` resources, the tag value, and the description |
| `vendor-role.tf` | `local.automat_target_ou` (one place; everything else references it) |
| `README.md` | prose only — no need to edit, but it will read oddly until you do |

A quick check from the bundle directory:

```
grep -rn ou-REPLACE-WITH-THE-NEW-OU-ID .
```

**A missed occurrence fails loudly rather than quietly.** The placeholder is not a
valid OU id, so AWS rejects a policy or template that still contains one. You
cannot end up with a role scoped to nothing.

## 3. Apply the bundle

Then follow `README.md`, and reply with both the role ARN and the OU id — the
requester needs the id for their own configuration.

## What the delegation ends up scoped to

```
organization o-exampleorgid
  management account 111111111111
    ...
      OU "Research Computing", id <the id from step 1>   <- the delegated subtree
        (vended accounts land here)
```

Account 222222222222 can act inside that subtree and nowhere else. Any service control
policy you attach at or above the parent still applies to everything in it.
