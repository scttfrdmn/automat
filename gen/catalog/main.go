// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/assess"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gen/catalog: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	out := flag.String("out", "catalogs", "directory to write compiled catalogs into")
	src := flag.String("sources", filepath.Join("gen", "sources"), "directory holding the curated source files")
	check := flag.Bool("check", false, "compile and compare against the vendored catalog without writing")
	flag.Parse()

	// Every catalog this tool knows how to build. A list rather than a single
	// compile, because `make catalogs-check` is only meaningful over all of them:
	// a second catalog wired in as its own command would be a second thing to
	// remember to run, and the one that gets forgotten is the one that goes stale.
	targets := []func(string) (*artifact.Artifact, error){
		compileFrom,
		compileBaseline,
		compileFrom171r2,
	}

	for _, compileOne := range targets {
		a, err := compileOne(*src)
		if err != nil {
			return err
		}
		if err := emit(a, *out, *src, *check); err != nil {
			return err
		}
	}

	// The objectives catalog is a different document type (internal/assess's
	// ObjectivesCatalog, not artifact.Artifact — see compileobjectives.go's
	// header comment for why), so it cannot share the targets slice above or
	// emit's signature. Run and emitted separately, but still every time this
	// tool runs, for the same reason `make catalogs-check` needs to be
	// meaningful over ALL compiled catalogs at once.
	oc, err := compileFromObjectives(*src)
	if err != nil {
		return err
	}
	return emitObjectives(oc, *out, *src, *check)
}

// emitObjectives writes the compiled objectives catalog, or compares it
// against the vendored copy. Mirrors emit's shape for artifact.Artifact,
// duplicated rather than made generic over both types: the two document
// types' Write/Validate/hash methods have different signatures, and a
// shared emit would need an interface neither type is designed to satisfy
// for its own sake.
func emitObjectives(oc *assess.ObjectivesCatalog, out, src string, check bool) error {
	data, err := oc.MarshalIndented()
	if err != nil {
		return err
	}
	// objectives/ subdirectory, not the top level: the top level is reserved
	// for control-artifact-v1 documents (catalogs/embed.go's own comment on
	// why), and this is a different schema.
	path := filepath.Join(out, "objectives", oc.Catalog.ID+".json")

	if check {
		have, err := os.ReadFile(path) //nolint:gosec // maintainer tool reading its own output
		if err != nil {
			return fmt.Errorf("read vendored catalog %s: %w", path, err)
		}
		if string(have) != string(data) {
			return fmt.Errorf("%s is stale: recompiling %s from %s produces different bytes; run `make catalogs`",
				path, oc.Catalog.ID, src)
		}
		fmt.Printf("%s up to date (%s)\n", path, oc.Catalog.ContentHash)
		return nil
	}

	if err := oc.Write(path); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  content_sha256 %s\n  %d requirements, %d objectives\n",
		path, oc.Catalog.ContentHash, len(oc.Requirements), countObjectives(oc))
	return nil
}

func countObjectives(oc *assess.ObjectivesCatalog) int {
	n := 0
	for _, r := range oc.Requirements {
		n += len(r.Objectives)
	}
	return n
}

// emit writes a compiled catalog, or compares it against the vendored copy.
func emit(a *artifact.Artifact, out, src string, check bool) error {
	data, err := a.MarshalIndented()
	if err != nil {
		return err
	}
	path := filepath.Join(out, a.Meta.ID+".json")

	if check {
		have, err := os.ReadFile(path) //nolint:gosec // maintainer tool reading its own output
		if err != nil {
			return fmt.Errorf("read vendored catalog %s: %w", path, err)
		}
		if string(have) != string(data) {
			return fmt.Errorf("%s is stale: recompiling %s from %s produces different bytes; run `make catalogs`",
				path, a.Meta.ID, src)
		}
		fmt.Printf("%s up to date (%s)\n", path, a.Meta.ContentHash)
		return nil
	}

	if err := a.Write(path); err != nil {
		return err
	}
	b := a.Breakdown()
	fmt.Printf("wrote %s\n  content_sha256 %s\n  %s\n", path, a.Meta.ContentHash, b.String())
	return nil
}

// compileFrom loads the curated sources and compiles the catalog.
func compileFrom(srcDir string) (*artifact.Artifact, error) {
	s, err := loadSources(srcDir)
	if err != nil {
		return nil, err
	}
	compiledAt, err := compiledAtFrom(s)
	if err != nil {
		return nil, err
	}
	return compile(s, compiledAt)
}
