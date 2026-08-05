// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package awsfake provides hand-written fakes for every interface in
// internal/awsapi.
//
// Its role in the vend pipeline is to make CLAUDE.md rule 1 enforceable: no test
// in this repository calls AWS, so every behavior the pipeline depends on has to
// be reproducible here. That includes the unhappy paths, which are the ones that
// matter — a vend that half-succeeds, an OU that cannot be moved into, a
// delegation policy the member side cannot see.
//
// No mocking framework, by choice. Each fake is a struct of scripted responses
// plus a call log, so a test says what the org looks like rather than what
// sequence of calls it expects. Tests that assert on call order tend to fail when
// an implementation is improved without changing what it does, and they do not
// catch the thing worth catching: the wrong conclusion drawn from a correct
// response.
//
// Every fake records its calls (see Recorder) because two properties automat
// claims are only checkable that way: that a plan-only run performs no mutation,
// and that a re-run of an idempotent step issues no redundant writes.
package awsfake
