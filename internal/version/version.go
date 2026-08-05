// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package version carries the build's identity.
//
// It has no role in the vend pipeline beyond one: the tool version is recorded
// in every evidence manifest record (DESIGN §11), so "which build made this
// claim" is answerable from the manifest alone.
package version

// Version is the build version, set via -ldflags at link time. It is "dev" in
// unstamped builds, including `go test` and `go run`.
var Version = "dev"
