// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/org"
	"github.com/scttfrdmn/automat/internal/safeio"
)

// attestationStubDirMode and attestationStubFileMode: an attestation stub
// holds no secret — it is a form the operator fills in by hand, and its
// content is at most a description of an institutional process — so unlike
// internal/evidence's manifestFileMode (0o600, chosen for a document that
// carries account ids and OU structure) these are the same narrow-by-default,
// operator-widenable defaults internal/bundle's own non-secret outputs use
// (dirMode/fileMode in internal/bundle/write.go), not internal/safeio's
// SecretDirMode/SecretFileMode. Nothing here refuses a wider mode the way
// safeio.ReadSecret refuses one, because nothing written here is a
// credential.
const (
	attestationStubDirMode  fs.FileMode = 0o700
	attestationStubFileMode fs.FileMode = 0o600
)

// reControlIDStubName is deliberately narrower than a control id is allowed
// to be — artifact.Control.ID carries no character-class restriction at all
// (internal/artifact/validate.go's control.validate only checks for
// emptiness). This is CLAUDE.md rule 8's round-trip discipline, not
// injection prevention: a stub's filename is a value automat writes that an
// operator reads back, tab-completes, and types onto a command line while
// filling the stub in by hand, so it is refused the moment it would carry a
// character that breaks either of those (a quote, a space, a slash). Every
// id in every catalog this repo ships (e.g. "AC.L1-b.1.i", "3.1.1") already
// matches it; the check exists for the catalog that will not.
var reControlIDStubName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// StubbedGroup names one deduped attestation group's stub file and the
// control ids it satisfies. EnsureAttestationStubs returns one of these per
// group so a later slice (ROADMAP's slice 7, evidence/manifest wiring) can
// populate evidence.Enforcement.AttestationIDs from the return value rather
// than re-deriving which control ids were stubbed by re-listing the
// directory and parsing filenames back into ids.
type StubbedGroup struct {
	// ControlIDs is the group's own DedupedAttestation.ControlIDs, carried
	// through unchanged.
	ControlIDs []string
	// FileName is the stub's basename (no directory), e.g. "3.1.1.md" —
	// deterministic from ControlIDs[0]; see EnsureAttestationStubs' doc
	// comment for why that is both deterministic and collision-free across
	// the groups one DedupeAttestations call returns.
	FileName string
}

// EnsureAttestationStubs writes one Markdown stub per deduped attestation
// group under dir, resolved beneath the current working directory the same
// way internal/evidence.OpenDir resolves baseline.evidence.local_dir — see
// that type's doc comment for the base/rel trust-boundary reasoning this
// reuses verbatim, because dir here is baseline.attestations.local_dir, the
// identical kind of document-supplied relative path (AUDIT-2 H1's lesson:
// the directory a birth certificate names and the directory automat actually
// wrote to must be resolved once, through one descriptor, or they can
// silently disagree).
//
// No AWS call at all, unlike every other method on this type — see the
// package doc's closing section and ROADMAP.md's own note that this slice
// "could land first regardless of numbering" for exactly that reason. Still
// an Ensurer method rather than a free function: a manifest reader should
// not need a different vocabulary (org.Action, org.Verb, e.Mode) for a
// pipeline stage that feeds the same evidence chain as every other stage —
// the same reasoning EnsureAutomationRole's own doc comment gives.
//
// # Filename: the group's own first control id, sorted
//
// compilesets.DedupeAttestations sorts each group's ControlIDs and sorts the
// returned groups by their own first id (crosswalk.go's mergeGroup and
// DedupeAttestations), so ControlIDs[0] is deterministic across repeated
// calls with the SAME artifact set. It is also collision-free across the
// groups one such call returns: two groups sharing a control id would be
// the same connected component under DedupeAttestations' own union-find, and
// therefore the same group, not two. Distinctness across DIFFERENT calls —
// two profiles naming different catalog combinations, both writing into the
// same directory — is not guarded here, and that is deliberate rather than
// an oversight: two profiles that both produce a group whose first id is
// (say) "3.1.1" are describing the same underlying practice under DESIGN
// §9's crosswalk semantics, so one shared stub for it is the intended
// outcome, not a name clash to avoid.
//
// # Idempotent: exists = unchanged, never overwritten, never diffed
//
// If the file already exists AND already carries content, this treats that
// as org.VerbUnchanged and touches nothing further — it does not compare the
// existing content against what would be rendered. An operator may have
// already filled the stub in by hand: written the real attestation text
// into the blank section this renderer leaves for them. Overwriting it on a
// later re-vend would destroy that work, which is the same class of harm
// org.EnsurePolicy's ownership-tag check exists to prevent for SCPs — a
// second apply must not clobber content a human has since taken ownership
// of. A flat file has no ownership-tag mechanism to check, so "content
// present means leave it alone, unconditionally, no diff" is the substitute.
//
// An existing but EMPTY file (an operator's `touch`, or this same call
// racing another instance of itself) is written into rather than skipped —
// see ensureOneStub's doc comment for why size, checked on the safely opened
// descriptor rather than by a separate stat-then-act, is the signal.
//
// # Plan mode reports VerbUnknown, not a real existence check
//
// A plan cannot check whether a stub already exists without resolving the
// directory that would hold it, and resolving that directory
// (safeio.EnsureDirUnder) is itself a create-if-missing operation — it would
// CREATE the directory and any missing intermediate component. Doing that in
// ModePlan would violate CLAUDE.md rule 5 ("no operation issues a mutating
// call in ModePlan") for a check whose only purpose is to describe what an
// apply would do. So plan mode reports VerbUnknown for every group and
// touches no filesystem at all — the same reason vendAutomationRoleStep's
// own plan-mode branch in cmd/automat/vend.go gives for not assuming into an
// account during a plan.
func (e *Ensurer) EnsureAttestationStubs(groups []compilesets.DedupedAttestation,
	dir string) ([]StubbedGroup, []org.Action, error) {
	if dir == "" {
		return nil, nil, fmt.Errorf("cannot write attestation stubs: no directory was given")
	}
	before := len(e.actions)
	if len(groups) == 0 {
		return nil, nil, nil
	}

	stubs := make([]StubbedGroup, 0, len(groups))
	for i := range groups {
		fileName, err := stubFileName(&groups[i])
		if err != nil {
			return nil, append([]org.Action(nil), e.actions[before:]...), err
		}
		stubs = append(stubs, StubbedGroup{
			ControlIDs: append([]string(nil), groups[i].ControlIDs...),
			FileName:   fileName,
		})
	}

	if e.planning() {
		for i := range groups {
			e.record(org.Action{
				Verb: org.VerbUnknown, Kind: "attestation stub", Name: stubs[i].FileName,
				Detail: "cannot be checked in plan mode without creating the directory that would " +
					"hold it, which a plan must not do. It would be created containing control ids " +
					strings.Join(groups[i].ControlIDs, ", ") + " if no file already exists at that " +
					"path with content in it, or left untouched if one does; apply to see which",
			})
		}
		return stubs, append([]org.Action(nil), e.actions[before:]...), nil
	}

	root, err := safeio.EnsureDirUnder(".", dir, attestationStubDirMode)
	if err != nil {
		return stubs, append([]org.Action(nil), e.actions[before:]...),
			fmt.Errorf("prepare the attestation stub directory %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	for i := range groups {
		if err := e.ensureOneStub(root, &groups[i], stubs[i].FileName, dir); err != nil {
			return stubs, append([]org.Action(nil), e.actions[before:]...), err
		}
	}
	return stubs, append([]org.Action(nil), e.actions[before:]...), nil
}

// StubFileName computes a group's deterministic filename, refusing a group
// whose leading control id cannot safely become one — see
// reControlIDStubName. Exported so internal/verify's procedural layer
// (CheckProcedural, ROADMAP.md's "internal/baseline, slices 2-9" item 9) can
// compute the SAME filename EnsureAttestationStubs would write for a given
// group, rather than re-deriving "ControlIDs[0]+\".md\"" a second time in a
// different package and risking the two definitions drifting apart.
func StubFileName(g *compilesets.DedupedAttestation) (string, error) {
	return stubFileName(g)
}

// stubFileName is StubFileName's unexported body — see its doc comment.
func stubFileName(g *compilesets.DedupedAttestation) (string, error) {
	if len(g.ControlIDs) == 0 {
		return "", fmt.Errorf("cannot write an attestation stub for a group with no control ids — " +
			"report this; compilesets.DedupeAttestations should never return one")
	}
	base := g.ControlIDs[0]
	if !reControlIDStubName.MatchString(base) {
		return "", fmt.Errorf("control id %s cannot become an attestation stub's filename: it would "+
			"carry a character an operator could not safely tab-complete or retype on a command "+
			"line (CLAUDE.md rule 8). Use only letters, digits, dot, dash, and underscore in a "+
			"control id that carries an attestation", safe(base))
	}
	return base + ".md", nil
}

// ensureOneStub creates fileName inside root's directory unless a file is
// already there and already carries content.
//
// # Why existence is checked with a read-only open first, rather than going
// straight to safeio.CreateChecked
//
// safeio.CreateChecked's existing-file branch calls chmodChecked
// unconditionally — correct for its existing caller (internal/evidence),
// which is about to overwrite the content anyway and wants the mode pinned
// to what it just wrote regardless of what it was. This caller does the
// opposite on the common path: leaves an existing, content-carrying stub
// completely alone. Calling CreateChecked on every re-vend would still reset
// an operator-widened mode back to attestationStubFileMode even though
// nothing about the CONTENT changed — a silent mode change this method's own
// "never touch what a human may have edited" promise should cover, since a
// mode is as much a hand-made choice as the prose inside the file.
//
// So this opens read-only first, through safeio.OpenChecked — the same
// checked-open discipline (symlink refusal, identity tie, no chmod) minus
// the write-specific checks CreateChecked layers on top for its own callers.
// A missing file (fs.ErrNotExist, unwrapped per OpenChecked's own doc) falls
// through to CreateChecked, which performs the actual first-write create.
// This is two name resolutions rather than one, but the first is read-only
// and its result changes nothing about safety: if something races between
// the two — the file that did not exist a moment ago now does — the second
// resolution (CreateChecked's own O_EXCL) is what decides, and it decides
// safely either way, the same as it always has for this file's counterpart
// in internal/evidence.
func (e *Ensurer) ensureOneStub(root *os.Root, g *compilesets.DedupedAttestation, fileName, dir string) error {
	shown := dir + "/" + fileName

	if pf, pfi, perr := safeio.OpenChecked(root, fileName, shown); perr == nil {
		size := pfi.Size()
		_ = pf.Close()
		if size > 0 {
			e.record(org.Action{
				Verb: org.VerbUnchanged, Kind: "attestation stub", Name: fileName,
				Detail: "already exists at " + shown + " and already carries content — automat " +
					"never overwrites an existing stub, and never touches its mode either, in case " +
					"an operator has already filled it in by hand",
			})
			return nil
		}
		// Falls through: an existing but empty file (e.g. an operator's `touch`)
		// has nothing to lose by being written into — see the method doc.
	} else if !errors.Is(perr, fs.ErrNotExist) {
		return fmt.Errorf("check whether attestation stub %s already exists: %w", shown, perr)
	}

	f, err := safeio.CreateChecked(root, fileName, shown, attestationStubFileMode)
	if f != nil {
		defer func() { _ = f.Close() }()
	}
	if err != nil {
		return fmt.Errorf("create attestation stub %s: %w", shown, err)
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("write attestation stub %s: %w", shown, err)
	}
	if _, err := f.Write([]byte(renderAttestationStub(g))); err != nil {
		return fmt.Errorf("write attestation stub %s: %w", shown, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush attestation stub %s: %w", shown, err)
	}

	e.record(org.Action{
		Verb: org.VerbCreate, Kind: "attestation stub", Name: fileName, ID: shown,
		Detail:  "created at " + shown + " for control ids " + strings.Join(g.ControlIDs, ", "),
		Applied: true,
	})
	return nil
}

// draftAttestationMarking mirrors internal/assess's draftMarking wording and
// purpose (internal/assess/render.go): a generated document must say plainly
// that it is not finished, so it is never mistaken for a completed
// attestation nobody has actually performed. This is a different claim from
// docs/policy-caveat.md's canonical paragraph (that one says a reading of
// policy is not a legal conclusion; this one says the document itself is
// unfinished), and both are needed for the same reason assess's own render.go
// carries both: a finished document can still not be a legal conclusion, and
// an unfinished one is not either, regardless.
const draftAttestationMarking = "DRAFT — attestation not yet completed"

// renderAttestationStub renders one group's fixed Markdown template. Not a
// templating system and not loaded from an external file (the task's own
// scope note): every group's stub is produced by the same Go string body,
// varying only in the fields substituted into it.
func renderAttestationStub(g *compilesets.DedupedAttestation) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("%s\n\n", draftAttestationMarking)
	w("# Attestation stub\n\n")
	w("Generated by automat. This file was created once and is never overwritten by a " +
		"later vend; edit it in place.\n\n")
	w("## Control ids satisfied by this practice\n\n")
	for _, id := range g.ControlIDs {
		w("- %s\n", id)
	}
	w("\n")

	if len(g.Crosswalk) > 0 {
		w("## Crosswalk\n\n")
		for _, fw := range sortedKeys(g.Crosswalk) {
			w("- %s: %s\n", fw, g.Crosswalk[fw])
		}
		w("\n")
	}

	w("## Frequency\n\n%s\n\n", g.Frequency)

	if g.Guidance != "" {
		w("## Guidance\n\n%s\n\n", g.Guidance)
	}

	w("## Attestation\n\n")
	w("_(blank — describe how this practice is implemented and how that is evidenced)_\n")

	return b.String()
}

// sortedKeys returns m's keys sorted, so the rendered crosswalk is
// deterministic across runs — a map's iteration order is not, and a stub
// that reordered its own crosswalk lines on every vend would make a diff
// against a previous stub noisy for no reason.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// safe renders an untrusted string for an error message — the same
// discipline internal/artifact.safe, internal/evidence.safe, and
// internal/compilesets.safe each restate for their own package, because a
// control id is attacker-controlled in the threat model (it is read from a
// compiled catalog) and this package's own errors are read by an operator
// deciding what to fix.
func safe(s string) string {
	const max = 120
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}
