// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package bundle turns a preflight failure into an artifact somebody can act on.
//
// Its role in the vend pipeline is the MEMBER-without-grants exit (DESIGN §6):
// when preflight says a vend cannot proceed, `automat setup --request` writes a
// directory the operator sends to whoever runs the management account. The bundle
// is the product at that point — a tool that says "you lack permission" and stops
// has produced nothing, while one that emits the exact policy and role to create,
// with the blast-radius argument written out, has produced the thing that gets
// approved.
//
// # Every value in this package is treated as attacker-controlled
//
// The five files are not documents. `delegation-policy.json` is applied to an
// organization, `vendor-role.cfn.yaml` and `vendor-role.tf` are *executed* by a
// privileged operator in the management account, and the two markdown files are
// read by whoever decides whether to run them. A value that could inject a
// statement into the policy, a resource into the template, or a plausible-looking
// instruction into the README would be a privilege escalation with a human as the
// delivery mechanism — and the human is reading exactly the file the attacker
// wrote.
//
// So rendering is allowlist-first, not escape-first:
//
//  1. Every field of Request must match a strict pattern before anything is
//     rendered (see Request.Validate). A value that does not match is a hard
//     error naming the field; there is no sanitizing pass that "cleans" input,
//     because a cleaner that gets one case wrong fails silently while a validator
//     that gets one case wrong fails loudly.
//  2. The JSON policy is built from Go structs and marshaled by encoding/json, so
//     its structure cannot be altered by a field value even if the validator were
//     wrong.
//  3. The patterns admit no character that terminates a string, a line, or a
//     comment in JSON, YAML, HCL, or markdown: no quote, backslash, newline,
//     brace, or control byte survives any of them.
//
// Validation is the security control here. The templates assume their inputs are
// already safe, and that assumption is only sound because nothing reaches them
// unvalidated — a property TestNoTemplateSeesAnUnvalidatedValue asserts directly.
package bundle
