// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// The curated source files. Each one records the upstream document it was
// derived from, that document's SHA-256, and the URI it came from, so a compiled
// artifact's provenance chain reaches all the way back to an authoritative
// publication.
const (
	farSourceFile       = "far-52.204-21.json"
	crosswalkSourceFile = "cfr-170-crosswalk.json"
	awsSourceFile       = "aws-config-cmmc-l1.json"
)

// upstream is the provenance block shared by every curated source file.
type upstream struct {
	Catalog     string `json:"catalog,omitempty"`
	Mapping     string `json:"mapping,omitempty"`
	Version     string `json:"version"`
	URI         string `json:"uri"`
	RetrievedAt string `json:"retrieved_at"`
	SHA256      string `json:"upstream_sha256"`
	File        string `json:"upstream_file"`
}

// farDoc is the verbatim FAR 52.204-21 requirement text.
type farDoc struct {
	Comment string   `json:"_comment"`
	Source  upstream `json:"source"`
	Clauses []struct {
		Paragraph string `json:"paragraph"`
		Text      string `json:"text"`
	} `json:"clauses"`
}

// crosswalkDoc is the CMMC final-rule identifier set and its 800-171 R2
// equivalents, from 32 CFR 170.
type crosswalkDoc struct {
	Comment  string   `json:"_comment"`
	Source   upstream `json:"source"`
	Controls []struct {
		ID        string   `json:"id"`
		Domain    string   `json:"domain"`
		Paragraph string   `json:"paragraph"`
		R2        []string `json:"r2"`
	} `json:"controls"`
}

// awsDoc is the AWS Config rule set joined with AWS's published control mapping.
type awsDoc struct {
	Comment string     `json:"_comment"`
	Sources []upstream `json:"sources"`
	// AWSControlDescriptions is AWS's own wording per control id. Recorded for
	// traceability of the join; the artifact uses the authoritative FAR text.
	AWSControlDescriptions map[string]string `json:"aws_control_descriptions"`
	// AWSConfigMapping is keyed by the 800-171-style control id AWS publishes.
	AWSConfigMapping map[string][]string `json:"aws_config_mapping"`
	Rules            map[string]awsRule  `json:"rules"`
}

type awsRule struct {
	Identifier    string            `json:"identifier"`
	Name          string            `json:"name"`
	Parameters    map[string]string `json:"parameters,omitempty"`
	ResourceTypes []string          `json:"resource_types,omitempty"`
}

// sourceSet is every curated input to a compile, plus the hash of each curated
// file itself.
type sourceSet struct {
	far           farDoc
	farHash       string
	crosswalk     crosswalkDoc
	crosswalkHash string
	aws           awsDoc
	awsHash       string
}

// loadSources reads and hashes the curated source files.
//
// Both the curated file's own hash and the upstream document's hash are kept:
// the first proves what the compiler read, the second proves where it came from.
func loadSources(dir string) (*sourceSet, error) {
	var s sourceSet
	var err error
	if s.farHash, err = readJSONAndHash(filepath.Join(dir, farSourceFile), &s.far); err != nil {
		return nil, err
	}
	if s.crosswalkHash, err = readJSONAndHash(filepath.Join(dir, crosswalkSourceFile), &s.crosswalk); err != nil {
		return nil, err
	}
	if s.awsHash, err = readJSONAndHash(filepath.Join(dir, awsSourceFile), &s.aws); err != nil {
		return nil, err
	}
	if err := s.check(); err != nil {
		return nil, err
	}
	return &s, nil
}

// check validates the source set's internal consistency before any compile.
//
// These are the invariants that, if violated, would silently produce a catalog
// missing controls or mapping rules to the wrong requirement. Better to refuse
// to compile than to vend against a quietly wrong artifact.
func (s *sourceSet) check() error {
	if err := s.checkProvenance(); err != nil {
		return err
	}

	const wantClauses = 15
	if n := len(s.far.Clauses); n != wantClauses {
		return fmt.Errorf("%s: found %d requirement clauses, want %d — "+
			"CMMC 2.0 Level 1 is exactly the fifteen requirements of FAR 52.204-21(b)(1)(i)-(xv) "+
			"per 32 CFR 170.14(c)(2); re-extract the source", farSourceFile, n, wantClauses)
	}
	if n := len(s.crosswalk.Controls); n != wantClauses {
		return fmt.Errorf("%s: found %d controls, want %d", crosswalkSourceFile, n, wantClauses)
	}

	// Every crosswalk entry must line up with a FAR paragraph, and vice versa.
	farParas := make(map[string]bool, len(s.far.Clauses))
	for _, c := range s.far.Clauses {
		farParas[c.Paragraph] = true
	}
	for _, c := range s.crosswalk.Controls {
		if !farParas[c.Paragraph] {
			return fmt.Errorf("%s: control %s references FAR paragraph (%s), which %s does not contain",
				crosswalkSourceFile, c.ID, c.Paragraph, farSourceFile)
		}
		if len(c.R2) == 0 {
			return fmt.Errorf("%s: control %s has no 800-171 R2 equivalent; the crosswalk is what joins "+
				"AWS's published mapping to final-rule ids, so an empty entry would silently drop its Config rules",
				crosswalkSourceFile, c.ID)
		}
	}
	seen := make(map[string]bool, len(s.crosswalk.Controls))
	for _, c := range s.crosswalk.Controls {
		if seen[c.ID] {
			return fmt.Errorf("%s: duplicate control id %s", crosswalkSourceFile, c.ID)
		}
		seen[c.ID] = true
	}

	// Every rule AWS maps must exist in the rule set, or the compile would
	// reference a rule with no identifier or parameters.
	var missing []string
	for control, rules := range s.aws.AWSConfigMapping {
		for _, name := range rules {
			if _, ok := s.aws.Rules[name]; !ok {
				missing = append(missing, fmt.Sprintf("%s (mapped to %s)", name, control))
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%s: mapping references %d rule(s) absent from the conformance pack: %v",
			awsSourceFile, len(missing), missing)
	}
	return nil
}

// reUpstreamSHA256 matches a lowercase hex SHA-256, the only form an upstream
// hash may take.
var reUpstreamSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// checkProvenance refuses to compile from a source whose own provenance block is
// incomplete.
//
// Without this the compiler will happily emit `(sha256 )` into an artifact's
// source notes: the artifact then *looks* provenanced — a reviewer sees a URI and
// a hash field — while the upstream document it claims to derive from is
// unverifiable. Provenance that cannot be checked is worse than absent
// provenance, because it is trusted. AUDIT-0 finding H1.
func (s *sourceSet) checkProvenance() error {
	blocks := []struct {
		file string
		u    upstream
	}{
		{farSourceFile, s.far.Source},
		{crosswalkSourceFile, s.crosswalk.Source},
	}
	for i, u := range s.aws.Sources {
		blocks = append(blocks, struct {
			file string
			u    upstream
		}{fmt.Sprintf("%s sources[%d]", awsSourceFile, i), u})
	}
	if len(s.aws.Sources) == 0 {
		return fmt.Errorf("%s records no upstream sources; the mapping's provenance is what vouches for "+
			"every aws-mapping binding in the catalog", awsSourceFile)
	}

	for _, b := range blocks {
		if b.u.Catalog == "" && b.u.Mapping == "" {
			return fmt.Errorf("%s: provenance block names neither a catalog nor a mapping; "+
				"artifact.sources needs the kind of input to record it", b.file)
		}
		switch {
		case b.u.SHA256 == "":
			return fmt.Errorf("%s: provenance block has no upstream_sha256; the compiled artifact would "+
				"claim a source it cannot prove, which reads as verified provenance to a reviewer", b.file)
		case !reUpstreamSHA256.MatchString(b.u.SHA256):
			return fmt.Errorf("%s: upstream_sha256 %q is not 64 lowercase hex characters", b.file, b.u.SHA256)
		}
		if b.u.URI == "" {
			return fmt.Errorf("%s: provenance block has no uri; a hash with no location cannot be re-fetched "+
				"and re-verified", b.file)
		}
		if b.u.RetrievedAt == "" {
			return fmt.Errorf("%s: provenance block has no retrieved_at; the compile timestamp is derived "+
				"from it so that %s is reproducible", b.file, artifactID)
		}
	}
	return nil
}

// artifactSources renders the provenance entries for a compiled artifact.
//
// Both layers appear: the curated file automat's compiler actually read, and the
// upstream publication it was derived from. A reviewer can therefore verify the
// chain without trusting the compiler.
//
// # Which document each hash is of, said in the entry (AUDIT-2)
//
// sha256 is the hash of the CURATED FILE, and uri names the UPSTREAM publication.
// Those are different documents, and the entry has one hash field and one uri
// field, so the note has to close the gap — otherwise a reviewer fetches the uri,
// hashes what comes back, gets a different value, and concludes the provenance is
// wrong. That is F6's failure mode in the classification profiles, found in the same
// audit, and it reached this compiler too: the two catalog entries named only the
// upstream ("curated from <uri> (sha256 ...)"), so nothing in the artifact said
// which bytes sha256 was over. The mapping entries already named their file.
//
// Both hashes stay recorded. The upstream one cannot become the sha256 field: the
// compiler never reads the upstream document — a curated file is a human
// transcription of it — so an artifact whose sha256 named bytes the compiler did not
// read would be a hash nothing in the build can check. What is fixed is the label.
func (s *sourceSet) artifactSources() []sourceEntry {
	out := []sourceEntry{
		{
			catalog:     s.far.Source.Catalog,
			version:     s.far.Source.Version,
			uri:         s.far.Source.URI,
			retrievedAt: s.far.Source.RetrievedAt,
			sha256:      s.farHash,
			note: fmt.Sprintf("verbatim requirement text. This entry's sha256 is of the curated file "+
				"gen/sources/%s, which is what the compiler read; it was transcribed from %s "+
				"(upstream sha256 %s), which is what the uri points at",
				farSourceFile, s.far.Source.URI, s.far.Source.SHA256),
		},
		{
			catalog:     s.crosswalk.Source.Catalog,
			version:     s.crosswalk.Source.Version,
			uri:         s.crosswalk.Source.URI,
			retrievedAt: s.crosswalk.Source.RetrievedAt,
			sha256:      s.crosswalkHash,
			note: fmt.Sprintf("control identifiers and 800-171 R2 crosswalk. This entry's sha256 is of the "+
				"curated file gen/sources/%s, which is what the compiler read; it was transcribed "+
				"from %s (upstream sha256 %s), which is what the uri points at",
				crosswalkSourceFile, s.crosswalk.Source.URI, s.crosswalk.Source.SHA256),
		},
	}
	for _, u := range s.aws.Sources {
		out = append(out, sourceEntry{
			mapping:     u.Mapping,
			version:     u.Version,
			uri:         u.URI,
			retrievedAt: u.RetrievedAt,
			sha256:      s.awsHash,
			note: fmt.Sprintf("enforcement mapping. This entry's sha256 is of the curated join "+
				"gen/sources/%s, which is what the compiler read and which is SHARED by every "+
				"mapping entry — two entries carrying the same hash is that join, not a "+
				"duplicate. It was built from %s (upstream sha256 %s), which is what the uri "+
				"points at", awsSourceFile, u.URI, u.SHA256),
		})
	}
	return out
}

// sourceEntry is a provenance entry before conversion to the artifact type.
type sourceEntry struct {
	catalog     string
	mapping     string
	version     string
	uri         string
	retrievedAt string
	sha256      string
	note        string
}

func readJSONAndHash(path string, into any) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // maintainer-run tool reading its own source tree
	if err != nil {
		return "", fmt.Errorf("read source %s: %w", path, err)
	}
	// Unknown fields are rejected. A misspelled key in a source file otherwise
	// parses cleanly and silently drops what it was carrying: "parmeters"
	// instead of "parameters" deletes a rule's parameter defaults, so the rule
	// deploys with AWS's defaults rather than the pack's — a control loosened by
	// a typo. AUDIT-0 finding H2.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return "", fmt.Errorf("parse source %s: %w — a misspelled or unrecognized key silently drops what "+
			"it carries, so the loader refuses it", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("parse source %s: unexpected trailing content after the JSON document", path)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
