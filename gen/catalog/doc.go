// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Command catalog compiles vendored control artifacts from the curated upstream
// sources in gen/sources.
//
// Its role in the vend pipeline is to be the only thing that ever reads an
// upstream catalog format. It runs at maintainer time, not vend time: automat
// itself only ever reads the compiled artifacts this writes into catalogs/. That
// split is what lets the artifact schema stay small and frozen while upstream
// formats churn.
//
// The compile is deterministic. Given the same source files it produces
// byte-identical output, including the content hash, which is what makes the
// golden-file test meaningful and what lets a reviewer diff two catalogs and see
// only real changes.
package main
