// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package broker assumes the vendor role a management account grants a member
// account (DESIGN §5) and turns the result into an aws.Config a caller can build
// an awsapi.OrgVendAPI client from.
//
// Its role in the vend pipeline is the MEMBER-state half of steps 2–4: creating
// the account, moving it, and creating an OU cannot be delegated to a member
// account at all (DESIGN §3, facts 1–2), so those calls borrow an identity in the
// management account instead. Policy management — step 4's SCP half — IS
// delegable and runs as the caller's own identity, never through this package.
// Collapsing the two into one client would erase the distinction that is the
// entire security argument the onboarding bundle makes: a member account gets a
// narrow, reviewable role for the parts of vending AWS will not delegate, and
// keeps its own identity for the rest.
//
// # What this package does not do
//
// It does not decide WHEN to broker. That is DESIGN §5's org-state question —
// STANDALONE and MANAGEMENT never call this package at all — and it lands at the
// call site (cmd/automat/globals.go's orgVendClient), not here.
//
// It does not manage session lifetime across a long-running operation. AssumeRole
// sessions cannot be extended, only re-assumed from scratch, and the vendor
// role's MaxSessionDuration is a fixed hour (internal/bundle/role.go). A single
// vend's create-move-OU sequence, including its poll loop for account creation,
// is nowhere near that bound in practice; a vend that somehow exceeds it fails
// like any other mid-vend interruption and resumes with `vend --resume
// <request-id>`. Assume is called once per vend. If wiring this into vend's poll
// loop later shows a real need for re-assumption, that is where it is added —
// building it here first would be speculative surface with no caller to justify
// it against.
//
// It does not resolve the ExternalId's shape or storage. internal/config already
// owns that (config.ResolveExternalID): the value is fetched at assume time from
// an env var or a file reference, never stored, and validated against AWS's
// charset and length before this package ever sees it. Assume takes the
// resolved reference and lets config do the resolving, so there is exactly one
// place that decides what counts as a usable ExternalId.
package broker
