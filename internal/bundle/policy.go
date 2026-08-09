// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The delegation policy: the "policy half" of DESIGN §5.
//
// A resource-based policy on the organization lets the management account hand a
// member account the ability to manage service control policies *on one OU
// subtree*, without making it an administrator of anything else. This is the half
// AWS Organizations supports natively; the vending half needs a role, because
// CreateAccount and CreateOrganizationalUnit are not delegable (DESIGN §3, facts
// 1 and 2).
//
// The policy is built from Go structs and marshaled by encoding/json rather than
// written as a template. A template with %s holes could, in principle, have a
// value close a string and open a statement; a marshaled struct cannot, whatever
// the value contains. Since this document is applied to an organization by a
// privileged operator, the structural guarantee is worth more than the readability
// of a template.

// policyDocument is an IAM/Organizations policy document.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Sid       string           `json:"Sid"`
	Effect    string           `json:"Effect"`
	Principal *policyPrincipal `json:"Principal,omitempty"`
	Action    []string         `json:"Action"`
	Resource  []string         `json:"Resource"`
	Condition map[string]any   `json:"Condition,omitempty"`
}

type policyPrincipal struct {
	AWS string `json:"AWS"`
}

// The policy actions, split by why each is needed so a reviewer can check the
// list against the argument rather than against a vibe.
var (
	// scpCreateActions bring a policy into existence. There is no existing
	// resource to carry a tag yet, so this is gated on the *request* tag: the
	// delegate may only create a policy that marks itself as automat's.
	//
	// TagResource is deliberately NOT here. See scpTagActions.
	scpCreateActions = []string{
		"organizations:CreatePolicy",
	}
	// scpModifyActions change or remove an existing policy, gated on the tag
	// already on it. This is the condition that stops the delegate touching an SCP
	// central IT wrote, even one attached to the same OU.
	scpModifyActions = []string{
		"organizations:UpdatePolicy",
		"organizations:DeletePolicy",
	}
	// scpTagActions write tags, and they are the sharpest edge in this policy.
	//
	// Every other statement here decides what the delegate may touch by reading
	// `automat:managed-by`. That is unavoidable: an Organizations policy ARN is
	// assigned at creation, so no ARN pattern can distinguish automat's SCPs from
	// central IT's — `policy/<org>/service_control_policy/*` matches all of them.
	// The tag is the only discriminator, which makes tag-write permission
	// equivalent to permission over everything the tag gates.
	//
	// So these are gated on the *resource* tag, never the request tag. Gating on
	// the request tag would read "you may apply automat's tag", which authorizes
	// applying it to central IT's SCP — and the delegate would inherit update,
	// delete, and detach over the institutional baseline. A condition that reads a
	// tag the caller may write constrains nothing. The aws:TagKeys bound is the
	// second half: without it the delegate could write tags outside automat's
	// namespace onto its own policies, forging conditions central IT relies on
	// elsewhere.
	scpTagActions = []string{
		"organizations:TagResource",
		"organizations:UntagResource",
	}
	// scpAttachActions attach and detach within the subtree.
	scpAttachActions = []string{
		"organizations:AttachPolicy",
		"organizations:DetachPolicy",
	}
	// readActions are the navigate-and-verify half. `verify` needs these, and
	// preflight uses them to tell an operator what they can do — a delegation
	// without them produces a tool that can change things it cannot report on.
	readActions = []string{
		"organizations:DescribeOrganization",
		"organizations:DescribeOrganizationalUnit",
		"organizations:DescribePolicy",
		"organizations:DescribeAccount",
		"organizations:DescribeEffectivePolicy",
		"organizations:ListRoots",
		"organizations:ListParents",
		"organizations:ListChildren",
		"organizations:ListOrganizationalUnitsForParent",
		"organizations:ListAccounts",
		"organizations:ListAccountsForParent",
		"organizations:ListPolicies",
		"organizations:ListPoliciesForTarget",
		"organizations:ListTargetsForPolicy",
		"organizations:ListTagsForResource",
	}
)

// DelegationPolicy renders delegation-policy.json.
//
// Four scoping mechanisms, each closing a different hole:
//
//   - The principal is the member account (or one role in it), so nobody else
//     gains anything.
//   - The resource list confines policy *attachment* to the delegated OU. Central
//     IT's own SCPs above that OU still bind everything below it, which is the
//     property the README's blast-radius argument rests on: the delegate can add
//     restrictions and can never loosen the institutional floor.
//   - A resource-tag condition confines policy *modification* to policies automat
//     created. Without it, "manage SCPs on this OU" would include central IT's own
//     SCP if it happened to be attached there — the delegate could detach the
//     institutional floor rather than merely add to it.
//   - Tag writes are themselves confined, by the same resource tag plus an
//     aws:TagKeys bound. This is the mechanism that makes the previous bullet
//     true rather than decorative, and it is the subtlest of the four: see
//     scpTagActions.
//
// The last two are the ones a reviewer is most likely to miss, so the generated
// README names the modification condition explicitly.
//
// # What is deliberately absent
//
// No statement permits attaching a policy to an *account* or to the organization
// root. An Organizations account ARN is
// arn:aws:organizations::<mgmt>:account/<org>/<id> — it encodes the organization,
// not the account's place in the OU tree — so `account/<org>/*` would match every
// account in the organization including central IT's, and an SCP is a deny
// instrument (DESIGN §3 fact 7). Attaching one to somebody else's account denies
// actions in it. automat attaches at the OU (DESIGN §5, §8), so account-level
// attachment is a capability it does not need and does not ask for.
func DelegationPolicy(r *Request) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}

	ou := r.ouScope()
	// Organizations policy ARNs are partition-scoped and account-scoped to the
	// management account; the wildcard is the policy id, which does not exist yet.
	// Note what this means: no ARN pattern can separate automat's SCPs from central
	// IT's, which is why the owner tag carries the whole distinction.
	policyARN := fmt.Sprintf("arn:aws:organizations::%s:policy/%s/service_control_policy/*",
		r.ManagementAccountID, r.OrgID)
	ouARN := fmt.Sprintf("arn:aws:organizations::%s:ou/%s/%s", r.ManagementAccountID, r.OrgID, ou)
	// Descendant OUs of the delegated one, so a sub-OU automat creates can carry
	// policies too. Still strictly inside the subtree.
	subOUARN := ouARN + "/*"
	rootARN := fmt.Sprintf("arn:aws:organizations::%s:root/%s/*", r.ManagementAccountID, r.OrgID)
	accountARN := fmt.Sprintf("arn:aws:organizations::%s:account/%s/*", r.ManagementAccountID, r.OrgID)

	principal := &policyPrincipal{AWS: r.trustPrincipal()}
	// The tag that marks a policy as automat's, per DESIGN §14's convention.
	const ownerTagKey = "aws:ResourceTag/automat:managed-by"
	ownedByAutomat := map[string]any{
		"StringEquals": map[string]any{ownerTagKey: "automat"},
	}

	doc := policyDocument{
		Version: "2012-10-17",
		Statement: []policyStatement{
			{
				Sid:       "AutomatCreatePoliciesMarkedAsItsOwn",
				Effect:    "Allow",
				Principal: principal,
				Action:    scpCreateActions,
				Resource:  []string{policyARN},
				// The request tag is the only option here: the policy does not
				// exist yet, so there is no resource tag to read. Both halves are
				// required — the value, so the new policy is automat's, and the key
				// bound, so creation cannot smuggle in an unrelated tag.
				Condition: map[string]any{
					"StringEquals": map[string]any{
						"aws:RequestTag/automat:managed-by": "automat",
					},
					"ForAllValues:StringLike": map[string]any{
						"aws:TagKeys": "automat:*",
					},
				},
			},
			{
				Sid:       "AutomatModifyOnlyPoliciesItCreated",
				Effect:    "Allow",
				Principal: principal,
				Action:    scpModifyActions,
				Resource:  []string{policyARN},
				Condition: ownedByAutomat,
			},
			{
				Sid:       "AutomatTagOnlyItsOwnPoliciesAndOnlyInItsOwnNamespace",
				Effect:    "Allow",
				Principal: principal,
				Action:    scpTagActions,
				Resource:  []string{policyARN},
				// Gated on the tag already present, not on the tag being applied.
				// The difference is the whole finding: the request-tag form would
				// let the delegate stamp automat's tag onto central IT's SCP and
				// inherit every grant above.
				Condition: map[string]any{
					"StringEquals": map[string]any{ownerTagKey: "automat"},
					"ForAllValues:StringLike": map[string]any{
						"aws:TagKeys": "automat:*",
					},
				},
			},
			{
				Sid:       "AutomatAttachItsPoliciesWithinTheDelegatedSubtree",
				Effect:    "Allow",
				Principal: principal,
				Action:    scpAttachActions,
				// Both halves are required: the policy being attached must be
				// automat's, and the target must be the delegated OU or one below
				// it. No account and no root target — see the note above.
				Resource:  []string{policyARN, ouARN, subOUARN},
				Condition: ownedByAutomat,
			},
			{
				Sid:       "AutomatReadTheOrganizationItOperatesIn",
				Effect:    "Allow",
				Principal: principal,
				Action:    readActions,
				// Read actions span the org: naming an OU means resolving its
				// parents, and `verify` reports on the accounts it vended. This is
				// the one statement wider than the OU, and it grants visibility
				// only — TestReadStatementIsScopedButHarmless holds that line.
				Resource: []string{rootARN, ouARN, subOUARN, accountARN, policyARN},
			},
		},
	}

	return marshalPolicyDocument(doc)
}

// marshalPolicyDocument renders a policyDocument the same way every JSON policy
// in this package does, so the escaping rule below has exactly one definition.
func marshalPolicyDocument(doc policyDocument) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// The policy is read by a human before it is applied, or applied directly by
	// EnsureVendorRole/EnsureDelegationPolicy with no human in the loop at all —
	// either way, escaping < > & into < would make it look like it contains
	// something it does not.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("render policy document: %w", err)
	}
	return buf.Bytes(), nil
}
