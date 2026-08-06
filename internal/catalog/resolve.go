// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/catalogs"
	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/envprofile"
)

// BaselineProtectionID is the control set every vend compiles in whether the
// environment profile names it or not (DESIGN §10).
const BaselineProtectionID = "baseline-protection"

// obligationsDir is where obligation profiles live inside the catalog tree.
//
// A subdirectory rather than a prefix, because the id namespaces are separate and
// deliberately overlap: `cmmc-l1` is both a control artifact (which controls) and an
// obligation profile (under what instrument, assessed how). Two documents, one id,
// and the directory is what says which one a reference means.
const obligationsDir = "obligations"

// reID is the catalog id character class, and it is the SAME class
// `schema/environment-profile-v1.schema.json` publishes for `control_sets[]` and for
// an obligation reference's id.
//
// Duplicated deliberately rather than imported from internal/envprofile, which keeps
// its own unexported copy: this package must be able to refuse an id it was handed
// by any caller, including one that skipped validation, and a resolver whose only
// defense is somebody else's check is a resolver with no defense. Drift between the
// two is caught by TestIDClassMatchesTheSchema, which reads the pattern out of the
// published schema rather than out of either copy.
var reID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

// Options selects which catalog tree to resolve against.
type Options struct {
	// FS is the filesystem holding the catalogs. Zero value means the embedded
	// tree, which is what every non-test caller wants.
	FS fs.FS
	// SkipHashCheck loads artifacts without verifying their declared content hash.
	// For tests that construct a deliberately inconsistent catalog; no command
	// sets it.
	SkipHashCheck bool
}

func (o Options) fsys() fs.FS {
	if o.FS != nil {
		return o.FS
	}
	return catalogs.FS()
}

// ResolveError reports that an id names no document, or that the document it names
// will not load.
//
// An error value with remediation text (CLAUDE.md rule 7). The remediation for an
// unresolvable id is to fix the environment profile or vendor the catalog, and
// Available is what makes that actionable — an operator who mistyped `cmcc-l1` needs
// the list, not a restatement of what they typed.
type ResolveError struct {
	// Kind is the document type that could not be resolved, for the error's first
	// clause: "control set" or "obligation profile".
	Kind string
	// ID is the id that failed. Rendered quoted: it comes from a file.
	ID string
	// Reason is what went wrong.
	Reason string
	// Remediation is the operator's next action.
	Remediation string
	// Available is every id of this kind the catalog tree does hold, sorted. Empty
	// when the failure was not a lookup.
	Available []string
	// Err is the underlying load or validation failure, when there was one.
	Err error
}

func (e *ResolveError) Error() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s: %s", e.Kind, safe(e.ID), e.Reason)
	if len(e.Available) > 0 {
		fmt.Fprintf(&sb, " (available: %s)", strings.Join(e.Available, ", "))
	}
	if e.Remediation != "" {
		fmt.Fprintf(&sb, ". %s", e.Remediation)
	}
	return sb.String()
}

func (e *ResolveError) Unwrap() error { return e.Err }

// Resolved is what a profile's control sets resolved to.
type Resolved struct {
	// IDs are the ids resolved, sorted and deduplicated, including
	// BaselineProtectionID whether or not the profile named it.
	IDs []string
	// Artifacts are the loaded artifacts in IDs order. Positionally aligned with
	// IDs so a caller reporting on one can name the other.
	Artifacts []*artifact.Artifact
}

// ResolveControlSets loads the control artifacts an environment profile's
// `control_sets` names, plus the baseline-protection meta-control.
//
// # baseline-protection is not optional
//
// It is appended whether or not the profile listed it, for two reasons that arrive at
// the same place. DESIGN §7 step 4 attaches it at every vend and §10 calls it the
// control set that guards the guards — a meta-control a document could disable by
// omission would not be one. And the packer requires it the moment the profile sets
// `permitted.regions` or `permitted.services`: those Deny shapes must spare the
// globally addressed services, the exemption list is catalog data rather than a
// hardcoded list (DESIGN §8), and `baseline-protection.json` is the artifact carrying
// it. A resolver that honored the profile literally would produce a plan-time refusal
// from Pack for a reason no operator could act on, since the missing input is not
// something the profile is supposed to name.
//
// # The order is canonical, not the profile's
//
// Ids are sorted and deduplicated. Merge is commutative and associative by
// construction (DESIGN §9), so order cannot change what is enforced — but it can
// change the origin lists in a conflict report and the bytes of an error message,
// and two runs of the same vend must produce the same text.
func ResolveControlSets(ids []string, opts Options) (*Resolved, error) {
	want := sortedUnique(append(append([]string(nil), ids...), BaselineProtectionID))

	out := &Resolved{
		IDs:       want,
		Artifacts: make([]*artifact.Artifact, 0, len(want)),
	}
	fsys := opts.fsys()
	for _, id := range want {
		p, err := documentPath(fsys, "control set", id, "")
		if err != nil {
			return nil, err
		}
		a, err := artifact.LoadFS(fsys, p, artifact.LoadOptions{SkipHashCheck: opts.SkipHashCheck})
		if err != nil {
			return nil, &ResolveError{
				Kind: "control set", ID: id,
				Reason: "will not load",
				Remediation: "the catalogs are compiled and vendored by `make catalogs` and verified by " +
					"`make catalogs-check`; a vendored catalog that does not load is a build problem rather " +
					"than something to work around at vend time",
				Err: err,
			}
		}
		if a.Meta.ID != id {
			// The filename is how an id is resolved, so a file whose interior id
			// differs makes the same document reachable under two names — and the
			// SCP tag, the account tag, and the evidence record all quote the
			// interior one. gen/catalog writes the file named for the id it
			// compiled, so this is unreachable for a vendored catalog and reachable
			// for a hand-supplied tree.
			return nil, &ResolveError{
				Kind: "control set", ID: id,
				Reason: fmt.Sprintf("resolved to a document whose own id is %s", safe(a.Meta.ID)),
				Remediation: "rename the file to match the artifact id, or the same control set is " +
					"reachable under two names while every tag and evidence record it produces quotes " +
					"only one of them",
			}
		}
		out.Artifacts = append(out.Artifacts, a)
	}
	return out, nil
}

// ResolveObligations loads the obligation profiles an environment profile references
// and returns the facts envprofile.CheckObligations needs.
//
// # No Go types, on purpose
//
// Obligation profiles are vendored data with no Go model (ROADMAP Phase 4 stage 0:
// "data and schema only, no Go types, no `assess`"), so this reads the two fields it
// needs out of raw JSON — the same way internal/artifact's obligation_profile_test.go
// does. A struct mirroring the schema here would be building what that decision said
// not to build, and would be a second reading of a document `assess` will have its
// own.
//
// # The hash is reported as UNKNOWN, and that is a real gap rather than an oversight
//
// `ObligationFacts.ContentSHA256` is left empty, which `CheckObligations` treats as
// "unknown" and never as "matches" — so a reference's `content_sha256` is checked for
// well-formedness by `Validate` and is not checked against the document. It cannot be:
// **`obligation-profile/v1` does not define what its content hash covers.** The
// control artifact defines a payload and the environment profile defines one; the
// obligation profile's schema names `signatures[].content_sha256` as "the document
// content hash" and never says which bytes that is. Choosing here — raw file bytes,
// or a canonicalized payload, and which fields it excludes — would be inventing a
// hashing contract for a published schema without the maintainer being asked, and
// getting it wrong makes every reference in every environment profile wrong in a way
// that only shows up once something checks.
//
// Recorded as Q15 in docs/open-questions.md. What is NOT done here is quietly
// reporting a hash computed some plausible way, because a reference that verified
// against the wrong definition is worse than one that verified against nothing: the
// first looks checked.
func ResolveObligations(ids []string, opts Options) (envprofile.ObligationSet, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	fsys := opts.fsys()
	out := make(envprofile.ObligationSet, len(ids))
	for _, id := range sortedUnique(ids) {
		p, err := documentPath(fsys, "obligation profile", id, obligationsDir)
		if err != nil {
			return nil, err
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return nil, &ResolveError{
				Kind: "obligation profile", ID: id,
				Reason:      "will not read",
				Remediation: "the shipped profiles live in catalogs/obligations; re-vendor the tree",
				Err:         rerr,
			}
		}
		facts, ferr := obligationFacts(id, data)
		if ferr != nil {
			return nil, ferr
		}
		out[id] = facts
	}
	return out, nil
}

// obligationDoc is the minimum shape ResolveObligations reads. Not a model of the
// schema: `additionalProperties: false` in the schema is what bounds a profile, and a
// second definition here would be one to keep in step for no gain.
type obligationDoc struct {
	Profile struct {
		ID string `json:"id"`
	} `json:"profile"`
	ControlCatalogs []struct {
		RevisionPolicy string `json:"revision_policy"`
	} `json:"control_catalogs"`
}

// revisionPolicyOperatorDetermined is the value that makes a revision the operator's
// to declare. Mirrors the schema's enum; the other value is `pinned`.
const revisionPolicyOperatorDetermined = "operator-determined"

func obligationFacts(id string, data []byte) (envprofile.ObligationFacts, error) {
	var doc obligationDoc
	// Unknown fields are tolerated here and nowhere else in automat, because this
	// reads two fields out of a document it does not model: rejecting the rest would
	// be asserting a shape this package deliberately does not know. The document is
	// validated against the published schema in internal/artifact's tests, which is
	// where a malformed profile is caught.
	if err := json.Unmarshal(data, &doc); err != nil {
		return envprofile.ObligationFacts{}, &ResolveError{
			Kind: "obligation profile", ID: id,
			Reason:      "is not parseable JSON",
			Remediation: "re-vendor the profile; a profile automat cannot parse is one nobody has read",
			Err:         err,
		}
	}
	if doc.Profile.ID != id {
		return envprofile.ObligationFacts{}, &ResolveError{
			Kind: "obligation profile", ID: id,
			Reason: fmt.Sprintf("resolved to a document whose own id is %s", safe(doc.Profile.ID)),
			Remediation: "rename the file to match the profile id. TestProfileIDMatchesFilename holds " +
				"this for the vendored set, so a mismatch means a hand-supplied tree",
		}
	}
	facts := envprofile.ObligationFacts{ID: id}
	for _, c := range doc.ControlCatalogs {
		if c.RevisionPolicy == revisionPolicyOperatorDetermined {
			// Any, not all: the obligation is unsatisfiable while one catalog's
			// revision is undeclared, and an environment profile carries one
			// determination per obligation. See ObligationFacts's own comment.
			facts.RequiresRevisionDetermination = true
			break
		}
	}
	return facts, nil
}

// documentPath turns an id into a path inside the catalog tree, refusing anything
// that is not an id before it becomes one.
//
// The order is the security property: the character class is checked FIRST, so no
// value that could traverse ever reaches path.Join. fs.ValidPath afterwards is belt
// and braces — reID admits neither `.` nor `/`, so a traversal is already
// unrepresentable — and it is cheap insurance against the class being loosened later
// by someone who did not read this comment.
func documentPath(fsys fs.FS, kind, id, dir string) (string, error) {
	if !reID.MatchString(id) {
		return "", &ResolveError{
			Kind: kind, ID: id,
			Reason: "is not a catalog id",
			Remediation: "ids are lowercase letters, digits, and hyphens, 2 to 64 characters, as the " +
				"vendored catalogs are named — cmmc-l1, 800-171r2, baseline-protection. An id becomes a " +
				"path, so a value outside that class is refused before it is one rather than after",
		}
	}
	p := path.Join(dir, id+".json")
	if !fs.ValidPath(p) {
		return "", &ResolveError{
			Kind: kind, ID: id,
			Reason:      "does not resolve to a path inside the catalog tree",
			Remediation: "this is a programming error in automat, not something a profile can cause; report it",
		}
	}
	if _, err := fs.Stat(fsys, p); err != nil {
		return "", &ResolveError{
			Kind: kind, ID: id,
			Reason:      "names no document in the catalog tree",
			Remediation: remediationFor(kind),
			Available:   available(fsys, dir),
		}
	}
	return p, nil
}

func remediationFor(kind string) string {
	if kind == "obligation profile" {
		return "check the id against the shipped profiles, or vendor the profile. An unresolvable " +
			"reference is not a weaker claim than a resolved one — it is a claim about a document " +
			"nobody has read"
	}
	return "check the id, or compile and vendor the control set with `make catalogs`. A vend that " +
		"skipped a control set it could not find would produce an account whose birth certificate " +
		"claims a posture nothing enforced"
}

// available lists the ids present in one directory of the tree, sorted.
//
// Best effort: a tree that cannot be listed still produces the not-found error, just
// without the list. An unreadable catalog directory is not a second failure to
// report — it is the same one, and replacing a specific "names no document" with a
// generic read error would tell the operator less.
func available(fsys fs.FS, dir string) []string {
	d := dir
	if d == "" {
		d = "."
	}
	entries, err := fs.ReadDir(fsys, d)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(out)
	return out
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// safe renders a catalog-supplied string for an error message.
//
// Same discipline as artifact.safe and evidence.safe: an id reaches here from a file
// that is attacker-controlled in the threat model, while this package's errors are
// read by an operator deciding what to fix. %q escapes newlines and control bytes, so
// an id cannot forge a line of a report.
func safe(s string) string {
	const max = 120
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}
