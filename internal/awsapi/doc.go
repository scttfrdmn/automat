// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package awsapi declares the narrow interfaces every AWS call in automat goes
// through, and turns AWS permission failures into errors that say what to grant.
//
// Its role in the vend pipeline is to be the only place the SDK is named. One
// interface per service concern, each holding just the operations automat calls,
// so `internal/preflight`, `internal/org`, `internal/broker`, and
// `internal/baseline` depend on a handful of methods rather than on a client.
// That is what makes `internal/awsfake` possible without a mocking framework,
// and it is what makes CLAUDE.md rule 1 — never call real AWS in tests —
// structurally true rather than a habit.
//
// The interfaces take the SDK's own input and output types. Wrapping those in
// project-local structs would double the surface to keep in sync and would let a
// fake drift from the shape the real API returns, which is the one thing a fake
// must not do.
package awsapi
