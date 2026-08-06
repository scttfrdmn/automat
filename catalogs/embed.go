// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package catalogs is the vendored compiled control artifacts and obligation
// profiles, embedded into the binary.
//
// It holds no logic. The only reason a data directory is also a Go package is
// that `//go:embed` cannot reach outside the package directory, and the data has
// to be inside the binary: DESIGN's first project fact is a single static binary,
// so a vend that read `catalogs/*.json` off disk would work from a source
// checkout and fail from `go install`. Resolution — which id maps to which
// document, and what happens when one is missing — lives in
// `internal/catalog`, which reads this.
//
// Vendored rather than fetched, and hashed rather than trusted: every artifact
// here carries a `content_sha256` over its canonicalized payload, and `make
// catalogs-check` fails if recompiling the curated sources in `gen/sources`
// produces different bytes. What the binary enforces is therefore reviewable in
// a diff.
package catalogs

import (
	"embed"
	"io/fs"
)

// files is the embedded tree: the compiled control artifacts at the top level
// and the obligation profiles below `obligations/`.
//
// Listed by glob rather than by name so that adding a catalog is a data change.
// A catalog that fails to embed is not a silent omission — `internal/catalog`
// refuses an id it cannot resolve, naming the file it looked for.
//
//go:embed *.json obligations/*.json
var files embed.FS

// FS returns the embedded catalog tree.
//
// A function returning fs.FS rather than an exported embed.FS variable: a package
// variable is assignable by any importer, and the whole value of embedding the
// catalogs is that what the binary enforces cannot be swapped at run time. An
// operator who wants to vend against their own catalog supplies it explicitly
// through internal/catalog's Options, which is a decision visible at the call
// site rather than a global that was reassigned somewhere.
func FS() fs.FS { return files }
