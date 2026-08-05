// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import "github.com/scttfrdmn/automat/internal/config"

// The ExternalId, and why this file is almost empty.
//
// # The bundle does not contain an ExternalId
//
// The role templates declare it as a deploy-time input — a CloudFormation `NoEcho`
// parameter, a Terraform `sensitive` variable — so whoever deploys the role chooses
// the value and tells the requester out of band. Nothing in the five generated files
// carries it, which is asserted directly by
// TestNoRenderedFileContainsAnExternalIDValue rather than left as a claim here.
//
// It used to work the other way. automat generated the value and interpolated it into
// both templates, which made the bundle a file carrying a live shared secret; the
// mitigation was a paragraph in the generated README telling the operator not to commit
// it. The AUDIT-1 review rejected that trade on the grounds that a paragraph is a
// weaker control than a mechanism. Inverting generation removes the secret from the
// artifact instead of asking a human to handle the artifact carefully, and what is left
// is an instruction to exchange one value out of band — a thing organizations already
// have a working process for.
//
// It also fixes an asymmetry that was easy to miss while reading either half alone: the
// party bearing the risk of a weak or leaked ExternalId is the management account
// granting the role, and under the old model the requester chose the value on their
// behalf. The grantor now chooses their own confused-deputy defense, which is the only
// party with standing to.
//
// # Why the value is not derived from anything
//
// A tempting design is to derive it from the account id and the OU, so both sides can
// recompute it and it never has to be transmitted at all. That is exactly wrong: those
// inputs are public, so anyone who can read the role's trust policy — or guess an
// account number — can recompute the value the trust policy checks. A derived
// ExternalId is a constant dressed as a secret. This is why the templates ask for an
// operator-supplied value rather than computing one from what they already know.
//
// # Where the rest of this went
//
// The generator and the placeholder check moved to internal/config, which is the side
// that now consumes the value: automat never chooses an ExternalId, it only resolves
// one at assume time. See config.ResolveExternalID.

// The bounds the role templates impose on the deploy-time ExternalId parameter.
//
// Aliases, not copies. These constrain a value automat did not generate and will later
// *consume* through config.ResolveExternalID, so the template's idea of an acceptable
// ExternalId and the resolver's must be the same idea — not two definitions that agree
// on the day they were written. An earlier draft of this file declared its own
// constants and a test to detect the drift; one constant with two readers is better
// than two constants with a referee.
const (
	minExternalIDChars = config.MinExternalIDChars
	maxExternalIDChars = config.MaxExternalIDChars
)

// externalIDPattern is the charset as a template-side pattern: CloudFormation anchors
// `AllowedPattern` implicitly, and Terraform's `regex()` is anchored explicitly at the
// call site. Length is carried by MinLength/MaxLength and by a `length()` validation
// respectively, rather than by a bounded repeat.
const externalIDPattern = config.ExternalIDCharset + `+`
