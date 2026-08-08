// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package classprofile

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/evidence"
)

// Problem is one validation failure.
//
// The same shape as artifact.Problem, evidence.Problem, and envprofile.Problem, and for
// the same reason (CLAUDE.md rule 7): Path says where, Message says what is wrong, Fix
// says what to change. A validation failure an operator cannot act on is a bug in the
// validator.
type Problem struct {
	Path    string
	Message string
	Fix     string
}

func (p Problem) Error() string {
	if p.Fix == "" {
		return fmt.Sprintf("%s: %s", p.Path, p.Message)
	}
	return fmt.Sprintf("%s: %s — %s", p.Path, p.Message, p.Fix)
}

// ValidationError collects every problem found in one pass.
type ValidationError struct {
	Subject  string
	Problems []Problem
}

func (v *ValidationError) Error() string {
	var sb strings.Builder
	subject := v.Subject
	if subject == "" {
		subject = "classification profile"
	}
	fmt.Fprintf(&sb, "%s is invalid (%d problem", subject, len(v.Problems))
	if len(v.Problems) != 1 {
		sb.WriteByte('s')
	}
	sb.WriteString("):")
	for _, p := range v.Problems {
		fmt.Fprintf(&sb, "\n  - %s", p.Error())
	}
	return sb.String()
}

// Unwrap exposes the problems to errors.Is/As traversal.
func (v *ValidationError) Unwrap() []error {
	out := make([]error, len(v.Problems))
	for i, p := range v.Problems {
		out[i] = p
	}
	return out
}

// AsValidationError extracts a *ValidationError from err, if there is one.
func AsValidationError(err error) (*ValidationError, bool) {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}

// UnknownLevelError is returned when a level id names no level of a profile.
//
// Its own type rather than a ValidationError, because the caller is asking about a
// level rather than about the document, and because listing the known ids is the whole
// remediation: a level id is a round-trip value, so the likeliest cause is a typo or a
// value typed from the wrong institution's scheme.
type UnknownLevelError struct {
	ProfileID string
	LevelID   string
	Known     []string
}

func (e *UnknownLevelError) Error() string {
	return fmt.Sprintf("classification profile %s has no level %s — its levels, least protective "+
		"first, are: %s. Level ids are per-institution and not comparable across profiles: a value "+
		"from another institution's scheme is not a level of this one",
		safe(e.ProfileID), safe(e.LevelID), strings.Join(e.Known, ", "))
}

type problems struct{ list []Problem }

func (p *problems) add(path, message, fix string) {
	p.list = append(p.list, Problem{Path: path, Message: message, Fix: fix})
}

// safe renders an untrusted string for inclusion in an error message.
//
// A classification profile is attacker-controlled input in the threat model — the whole
// point of "example-and-forkable" is that operators fork these, and a forked one may
// have travelled — and this validator's output is a multi-line bulleted list. A value
// containing a newline could forge additional lines of that list, and an ANSI escape
// could hide or recolor real ones, so a reviewer reads a clean report while the
// document is anything but. %q escapes newlines, control characters, and escape bytes,
// and marks the value as data rather than structure. Same defect and same fix as
// AUDIT-0's M1.
func safe(s string) string {
	const max = 120
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}

// Patterns mirror schema/classification-profile-v1.schema.json. The schema conformance
// test is what keeps them in step.
var (
	reSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reDate   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	reStamp  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	reBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	// Round-trip fields (CLAUDE.md rule 8): values automat WRITES that a person reads
	// back and types onto a command line. Not injection prevention — argument
	// construction is the CLI's problem — but a refusal to record a value whose whole
	// purpose is to travel through human hands into a shell.
	//
	// reSlug covers the profile id, the issuer id, the control ids, the source ids, and
	// the obligation profile ids an external-obligation reference names. The profile id
	// is how a document is found in a directory; the issuer id is the key an inherits
	// block is checked against and a value an operator groups profiles by.
	reSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	// reLevelID is the round-trip field an operator types MOST often: a rating is
	// recorded per account, so a level id travels from a policy document through
	// automat's output and back onto a command line. Bounded tighter than a slug at 32
	// characters, because a level id is a label like `p4` or `dsl3` and a 64-character
	// one is a sentence.
	reLevelID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)
	// Prose fields are rendered into reports, tables, and whatever states what an
	// account is rated for. A control byte in one forges a line of that output, so it
	// is refused here rather than escaped at each render site.
	reProse = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
	// long_prose permits newlines and tabs — a determination process and a
	// non-endorsement statement are paragraphs — but no other control byte.
	reLongProse = regexp.MustCompile(`^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$`)
)

// Limits mirroring the schema's maxLength, maxItems, minItems, and numeric bounds.
const (
	maxProse      = 512
	maxLongProse  = 8192
	maxSignatures = 16
	maxSigValue   = 16384
	maxRoles      = 16
	maxExamples   = 32
	maxControls   = 256
	maxExternal   = 32
	maxAxes       = 8
	// MinLevels is two. A scheme with one level does not classify anything: every
	// resource is rated for the only level there is, so the document records a fact
	// with no content while looking like a policy.
	MinLevels = 2
	// MaxLevels is well above the five the published schemes reach, so that a genuine
	// outlier is representable — but bounded, because a "scheme" with fifty levels is
	// a transcription error rather than a policy, and it would render as a wall
	// nobody reads.
	MaxLevels = 12
	// MaxRank bounds an individual rank. Ranks must additionally run 1..N with no
	// gaps, which is the check that matters; this bound only stops an absurd value
	// from being stated at all.
	MaxRank = 64
)

// Validate checks the profile against every constraint the schema expresses plus the
// within-document ones it cannot, returning a *ValidationError listing all of them.
//
// The within-document checks are the load-bearing half here, more so than for any other
// automat document, because the invariants that make a derived profile honest are all
// cross-field: that ranks form a dense order, that every citation resolves to a source
// this document actually hashed, that the non-endorsement statement names the institution
// it disclaims, and that a derived profile's attestations claim only interpretation. A
// schema can express none of those.
//
// It does NOT check whether each attestation names this document's hash — see
// VerifyAttestationSubjects. Separate for the reason envprofile's is: a validator that
// quietly did less than its name suggests is the shape of gap this project's tests exist
// to close.
func (p *Profile) Validate() error {
	var probs problems

	switch {
	case p.SchemaVersion == "":
		probs.add("schema_version", "missing", "set it to "+SchemaVersion)
	case !reSemver.MatchString(p.SchemaVersion):
		probs.add("schema_version", fmt.Sprintf("%s is not semver", safe(p.SchemaVersion)),
			"use MAJOR.MINOR.PATCH, e.g. "+SchemaVersion)
	case majorOf(p.SchemaVersion) != majorOf(SchemaVersion):
		probs.add("schema_version",
			fmt.Sprintf("major version %s is not supported by this build", majorOf(p.SchemaVersion)),
			"this build understands classification-profile schema "+majorOf(SchemaVersion)+
				".x; upgrade automat or update the profile")
	}

	p.Meta.validate(&probs)
	p.Issuer.validate(&probs)
	p.validateStatusAndAuthorship(&probs)
	p.validateReviewBy(&probs)
	p.validateInterpretation(&probs)
	p.Determination.validate(&probs)
	p.validateLevels(&probs)
	p.Composition.validate(&probs)
	p.validateInherits(&probs)
	p.validateUnmodeledAxes(&probs)
	p.validateCitations(&probs)
	p.validatePolicyCaveat(&probs)
	p.validateSources(&probs)
	p.validateSignatures(&probs)
	// Last, because it reads the source ids the check above has already reported on:
	// resolving a reference against a malformed source list would produce a second
	// error per citation about the same defect.
	p.validateCitationRefsResolve(&probs)

	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: p.subject(), Problems: probs.list}
}

func (p *Profile) subject() string {
	if p.Meta.ID == "" {
		return "classification profile"
	}
	return "classification profile " + safe(p.Meta.ID)
}

func majorOf(semver string) string {
	if i := strings.IndexByte(semver, '.'); i > 0 {
		return semver[:i]
	}
	return semver
}

func (m *Meta) validate(p *problems) {
	switch {
	case m.ID == "":
		p.add("classification_profile.id", "missing",
			"give the profile a stable id, e.g. \"uc-is3\"")
	case !reSlug.MatchString(m.ID):
		p.add("classification_profile.id", fmt.Sprintf("%s is not a valid id", safe(m.ID)),
			"use 2-64 characters of lowercase letters, digits, and hyphens, starting and ending "+
				"alphanumeric. The id is a round-trip value: an operator reads it back and types it")
	}
	checkProse(p, "classification_profile.title", m.Title, true,
		"give the profile a human-readable title")
	if m.Description != "" {
		checkLongProse(p, "classification_profile.description", m.Description)
	}
}

func (is *Issuer) validate(p *problems) {
	switch {
	case is.ID == "":
		p.add("issuer.id", "missing",
			"give the institution a stable id, e.g. \"uc\" or \"stanford\". Required: it is the key an "+
				"inherits block is checked against, so an overlay cannot be attributed to the wrong "+
				"institution")
	case !reSlug.MatchString(is.ID):
		p.add("issuer.id", fmt.Sprintf("%s is not a valid issuer id", safe(is.ID)),
			"use 2-64 characters of lowercase letters, digits, and hyphens. This is a round-trip "+
				"value: an operator groups profiles by it and types it")
	}
	checkProse(p, "issuer.name", is.Name, true,
		"name the institution as it names itself, e.g. \"University of California\". Required, and "+
			"rendered verbatim into the non-endorsement statement: a disclaimer that names no "+
			"institution is one a reader will attach to whichever institution they had in mind")
	if is.Unit != "" {
		checkProse(p, "issuer.unit", is.Unit, false, "")
	}
}

func (p *Profile) validateStatusAndAuthorship(probs *problems) {
	if !knownStatus(p.Status) {
		probs.add("status", fmt.Sprintf("%s is not one of the statuses", safe(string(p.Status))),
			"use one of: "+joinStatuses()+". A superseded scheme is recordable rather than deletable: "+
				"an account rated years ago was rated under whatever was current then")
	}
	if !knownAuthorship(p.Authorship) {
		probs.add("authorship", fmt.Sprintf("%s is not one of the authorship values",
			safe(string(p.Authorship))),
			"use one of: "+joinAuthorship()+". The two are not stylistic: they are the difference "+
				"between \"the institution says\" and \"automat's reading of what the institution "+
				"says\", and a reader who cannot tell them apart will assume the first")
	}
	if !knownMaintenance(p.Maintenance) {
		probs.add("maintenance", fmt.Sprintf("%s is not one of the maintenance values",
			safe(string(p.Maintenance))),
			"use one of: "+joinMaintenance())
		return
	}
	// The pairing, which the schema states as an `if/then` and this states as a
	// sentence: automat reads an institution's policy, it does not maintain that
	// institution's classification scheme, and a document saying otherwise invites an
	// operator to treat automat as the upstream.
	if p.Authorship == AuthorshipDerived && p.Maintenance != MaintenanceExample {
		probs.add("maintenance", fmt.Sprintf("is %s on a derived interpretation",
			safe(string(p.Maintenance))),
			"a derived profile must be "+string(MaintenanceExample)+". automat is the interpreter of "+
				"an institution's published policy, never the maintainer of that institution's "+
				"classification scheme, and a document claiming to be maintained would invite an "+
				"operator to treat automat as the upstream for it")
	}
}

func (p *Profile) validateReviewBy(probs *problems) {
	switch {
	case p.ReviewBy == "":
		probs.add("review_by", "missing",
			"set the date by which this profile must be re-read against the institution's published "+
				"policy, as YYYY-MM-DD. Required with no default: an institutional scheme moves less "+
				"than a federal clause but it does move, and a profile nobody re-reads keeps rating "+
				"accounts under a policy that changed")
	case !reDate.MatchString(p.ReviewBy):
		probs.add("review_by", fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(p.ReviewBy)),
			"a review date is a policy fact, not an event time; use the plain date form")
	}
}

// validateInterpretation checks the block that makes a derived profile honest.
//
// Both directions are hard errors. A derived profile without it is the failure this
// whole document type is shaped to prevent — automat's reading of an institution's
// policy circulating as the policy. An issuer-authored profile carrying it would be an
// institution disclaiming its own document, which is not a lesser defect: it would tell
// a reader that the institution had not endorsed a scheme the institution wrote.
func (p *Profile) validateInterpretation(probs *problems) {
	const path = "interpretation"
	if p.Authorship != AuthorshipDerived {
		if p.Interpretation != nil && knownAuthorship(p.Authorship) {
			probs.add(path, "is present on an "+string(AuthorshipIssuer)+" profile",
				"remove the block, or set authorship to "+string(AuthorshipDerived)+". An "+
					"institution does not disclaim its own document: a non-endorsement statement on a "+
					"profile the issuer wrote tells a reader the institution has not endorsed a scheme "+
					"it authored")
		}
		return
	}
	in := p.Interpretation
	if in == nil {
		probs.add(path, "missing on a "+string(AuthorshipDerived)+" profile",
			"a reading of someone else's published policy must disclose that it is one: name the "+
				"interpreter, the source it reads, the attribution the source requires, and the "+
				"non-endorsement statement. This is the block the whole document type exists for — "+
				"without it automat's reading of an institution's policy circulates as the policy")
		return
	}
	checkProse(probs, path+".interpreter", in.Interpreter, true,
		"name who produced the interpretation — the identity that would sign `interpreted-by`")
	switch {
	case in.SourceID == "":
		probs.add(path+".source_id", "missing",
			"name the sources[] entry this profile is a reading OF — the primary document, distinct "+
				"from any supporting source a single control cites")
	case !reSlug.MatchString(in.SourceID):
		probs.add(path+".source_id", fmt.Sprintf("%s is not a source id", safe(in.SourceID)),
			"use the lowercase-and-hyphens form the sources[] ids use")
	}
	if in.Attribution == "" {
		probs.add(path+".attribution", "missing",
			"credit the source in the terms the source itself sets — a copyright line, a terms-of-use "+
				"statement, a required notice")
	} else {
		checkLongProse(probs, path+".attribution", in.Attribution)
	}
	p.validateNonEndorsement(probs, path+".non_endorsement")
}

// NonEndorsementSubstance is the phrase list a non-endorsement statement must contain,
// held the same way docs/policy-caveat.md's requiredCaveatSubstance is.
//
// ROADMAP fixes the wording:
//
//	This is automat's interpretation of a published policy. It was not authored,
//	reviewed, or endorsed by <institution>. The institution's own policy governs;
//	verify against it.
//
// Asserted in substance rather than verbatim, for the reason the policy caveat is:
// renderers wrap differently, and a check that failed on a line break would be
// enforcing formatting while claiming to enforce meaning. Each phrase below is here
// because dropping it changes what the paragraph claims — "interpretation" is what makes
// it a reading rather than the policy; "not authored, reviewed, or endorsed" is the
// negative claim itself, and all three verbs matter because a reader who sees only "not
// authored" concludes the institution reviewed it; "governs" says whose document
// outranks whose; "verify against it" is what makes the reader's next action clear.
var NonEndorsementSubstance = []string{
	"interpretation",
	"not authored, reviewed, or endorsed",
	"governs",
	"verify against it",
}

// validateNonEndorsement checks the statement in substance, and checks that it names the
// institution.
//
// The institution's name is required IN the statement, which is the half a phrase list
// alone would miss: "It was not authored, reviewed, or endorsed by the institution" is a
// grammatically complete disclaimer that disclaims nobody, and a reader will attach it
// to whichever institution they had in mind.
func (p *Profile) validateNonEndorsement(probs *problems, path string) {
	stmt := p.Interpretation.NonEndorsement
	if stmt == "" {
		probs.add(path, "missing",
			"state, in substance: \"This is automat's interpretation of a published policy. It was "+
				"not authored, reviewed, or endorsed by <institution>. The institution's own policy "+
				"governs; verify against it.\"")
		return
	}
	checkLongProse(probs, path, stmt)
	if missing := MissingNonEndorsementSubstance(stmt); len(missing) > 0 {
		probs.add(path, fmt.Sprintf("is missing %v", missing),
			"each phrase in that list is there because dropping it changes what the statement "+
				"claims: \"interpretation\" is what makes this a reading rather than the policy, all "+
				"three verbs in \"not authored, reviewed, or endorsed\" matter because a reader who "+
				"sees only one concludes the institution did the others, \"governs\" says whose "+
				"document outranks whose, and \"verify against it\" is what makes the reader's next "+
				"action clear")
	}
	// Named institution, not a placeholder. Checked case-insensitively and only when
	// the name is long enough to be a name: a two-character issuer name would match
	// most sentences by accident.
	if name := strings.TrimSpace(p.Issuer.Name); len(name) >= 3 &&
		!strings.Contains(strings.ToLower(stmt), strings.ToLower(name)) {
		probs.add(path, fmt.Sprintf("does not name %s", safe(p.Issuer.Name)),
			"write the institution's name into the statement. A disclaimer that names no "+
				"institution is one a reader will attach to whichever institution they had in mind, "+
				"which is the opposite of what it is for")
	}
}

// MissingNonEndorsementSubstance reports which required phrases are absent, ignoring how
// the text is wrapped.
//
// Whitespace is collapsed first for the reason missingCaveatSubstance collapses it: a
// phrase broken across two lines by a hard wrap reads as missing, and a test that failed
// on a line wrap would be enforcing verbatim wording.
func MissingNonEndorsementSubstance(text string) []string {
	flat := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	var missing []string
	for _, phrase := range NonEndorsementSubstance {
		if !strings.Contains(flat, phrase) {
			missing = append(missing, phrase)
		}
	}
	return missing
}

// validate checks the who-decides block.
//
// AutomatDetermines is the load-bearing line. An automated "this dataset is Level 4" is
// the worst output this tool could produce: wrong in the permissive direction it tells
// an institution its regulated data is unregulated, and it would be believed, because it
// came from a tool that is right about everything else. So the field is pinned false at
// both layers, the same device as the obligation profile's `declared_by_operator: const
// true` pointing the other way.
func (d *Determination) validate(p *problems) {
	const path = "determination"
	if d.AutomatDetermines {
		p.add(path+".automat_determines", "is true",
			"set it to false. automat never classifies data: determination is a human role this "+
				"profile NAMES, and a profile cannot opt into the tool deciding. If an automated "+
				"determination is being designed here, stop and flag it — the decision to have no "+
				"such field rather than a tempting one was deliberate")
	}
	switch {
	case len(d.Roles) == 0:
		p.add(path+".roles", "empty",
			"name the roles the institution's policy makes responsible for determining a level — "+
				"\"Proprietors\", \"Unit Information Security Leads\". Required: naming the role is "+
				"what makes the absence of an automated determination a design rather than an "+
				"omission, and an operator recording a rating has to know whose determination it is")
	case len(d.Roles) > maxRoles:
		p.add(path+".roles", fmt.Sprintf("has %d entries; the schema permits %d", len(d.Roles), maxRoles),
			"")
	}
	seen := make(map[string]int, len(d.Roles))
	for i, r := range d.Roles {
		ipath := fmt.Sprintf("%s.roles[%d]", path, i)
		checkProse(p, ipath, r, true, "name the role as the source names it")
		if prev, dup := seen[r]; dup {
			p.add(ipath, fmt.Sprintf("duplicates %s.roles[%d]", path, prev), "list each role once")
		} else {
			seen[r] = i
		}
	}
	if d.Process == "" {
		p.add(path+".process", "missing",
			"describe the determination process as prose for a human, in the source's own terms. "+
				"Prose deliberately: a process expressed as steps a machine could walk is a matcher "+
				"with extra words, and the point of this field is to tell an operator who to ask")
	} else {
		checkLongProse(p, path+".process", d.Process)
	}
	d.Citation.validate(p, path+".citation")
	if d.MayRaise != "" && !knownPermission(d.MayRaise) {
		p.add(path+".may_raise", fmt.Sprintf("%s is not a permitted value", safe(string(d.MayRaise))),
			"use one of: "+joinPermissions()+", or omit the field where the source does not say")
	}
	if ml := d.MayLower; ml != nil {
		if !knownLowerPermission(ml.Permitted) {
			p.add(path+".may_lower.permitted",
				fmt.Sprintf("%s is not a permitted value", safe(string(ml.Permitted))),
				"use one of: "+joinLowerPermissions()+". \"only-by-exception\" is the answer most "+
					"published schemes actually give, and folding it into \"yes\" would read as "+
					"permission where the source describes a process")
		}
		if ml.ExceptionProcess != "" {
			checkProse(p, path+".may_lower.exception_process", ml.ExceptionProcess, false, "")
		}
		if ml.Permitted == LowerOnlyByException && ml.ExceptionProcess == "" {
			p.add(path+".may_lower.exception_process", "missing where lowering is only by exception",
				"name the process the source names, e.g. \"IS-3, III.2.2, Exception Process\". A "+
					"document that says an exception is required without saying which one sends an "+
					"operator looking for a process nobody identified")
		}
		if ml.Citation != nil {
			ml.Citation.validate(p, path+".may_lower.citation")
		}
	}
	if d.Notes != "" {
		checkLongProse(p, path+".notes", d.Notes)
	}
}

// validateLevels is where the rank discipline lives.
//
// Three checks, and the dense-order one is the reason the others are worth making. A
// schema can bound a rank and require it to be present; only a cross-field check can
// see that the ranks run 1..N with no gaps and no ties, and a gap is how a transcribed
// scheme silently loses a level — four entries ranked 1, 2, 4, 5 read as a complete
// four-level scheme while the document itself says a level is missing.
func (p *Profile) validateLevels(probs *problems) {
	switch {
	case len(p.Levels) < MinLevels:
		probs.add("levels", fmt.Sprintf("has %d entries; a scheme needs at least %d",
			len(p.Levels), MinLevels),
			"a scheme with one level does not classify anything: every resource is rated for the only "+
				"level there is, so the document records a fact with no content while looking like a "+
				"policy")
		return
	case len(p.Levels) > MaxLevels:
		probs.add("levels", fmt.Sprintf("has %d entries; the schema permits %d",
			len(p.Levels), MaxLevels),
			fmt.Sprintf("the published schemes run three to five levels. %d is a transcription error "+
				"rather than a policy, and it would render as a wall nobody reads", len(p.Levels)))
	}

	ids := make(map[string]int, len(p.Levels))
	ranks := make(map[int]int, len(p.Levels))
	labels := make(map[string]int, len(p.Levels))
	for i := range p.Levels {
		l := &p.Levels[i]
		path := fmt.Sprintf("levels[%d]", i)

		switch {
		case l.ID == "":
			probs.add(path+".id", "missing",
				"give the level a stable id, e.g. \"p4\", \"dsl3\", \"high\", or \"restricted\"")
		case !reLevelID.MatchString(l.ID):
			probs.add(path+".id", fmt.Sprintf("%s is not a level id", safe(l.ID)),
				"use 2-32 characters of lowercase letters, digits, and hyphens. This is the round-trip "+
					"value an operator types most often — a rating is recorded per account, so the id "+
					"travels from a policy document through automat's output and back onto a command "+
					"line, and one carrying whitespace cannot be selected by double-click")
		}
		if prev, dup := ids[l.ID]; dup && l.ID != "" {
			probs.add(path+".id", fmt.Sprintf("duplicates levels[%d].id", prev),
				"one entry per level: two levels with one id cannot be told apart by anything that "+
					"records a rating")
		} else if l.ID != "" {
			ids[l.ID] = i
		}

		checkProse(probs, path+".label", l.Label, true,
			"write the level as the institution writes it — \"P4 - High\", \"High Risk\", \"DSL 3\", "+
				"\"Restricted\". The institution's spelling rather than a normalized one: an operator "+
				"comparing automat's output against their own policy page is doing a string comparison "+
				"by eye")
		if prev, dup := labels[l.Label]; dup && l.Label != "" {
			probs.add(path+".label", fmt.Sprintf("duplicates levels[%d].label", prev),
				"two levels with one label are indistinguishable in every rendering, whatever their ids")
		} else if l.Label != "" {
			labels[l.Label] = i
		}

		switch {
		case l.Rank < 1:
			probs.add(path+".rank", fmt.Sprintf("is %d", l.Rank),
				"give the level an explicit integer rank, 1 being the least protective. Required with "+
					"no default and no inference: the published schemes sort OPPOSITE by name — U-M's "+
					"\"Restricted\" is the top of a list whose names run downward, while Harvard's DSL "+
					"1-5 and UC's P1-P4 run upward — so an implementation that ordered by label passes "+
					"on four of six schemes and silently rates an account at the wrong end of the "+
					"other two")
		case l.Rank > MaxRank:
			probs.add(path+".rank", fmt.Sprintf("is %d, over the %d limit", l.Rank, MaxRank), "")
		}
		if prev, dup := ranks[l.Rank]; dup {
			probs.add(path+".rank", fmt.Sprintf("duplicates levels[%d].rank", prev),
				"each level takes a distinct rank. Two levels at one rank make the order undefined "+
					"exactly where highest-water-mark composition has to choose between them")
		} else {
			ranks[l.Rank] = i
		}

		if l.Definition == "" {
			probs.add(path+".definition", "missing",
				"state what the level means, in the source's terms")
		} else {
			checkLongProse(probs, path+".definition", l.Definition)
		}
		l.Citation.validate(probs, path+".citation")
		p.validateLevelExamples(probs, path, l)
		p.validateLevelControls(probs, path, l)
		p.validateLevelObligations(probs, path, l)
		if l.Notes != "" {
			checkLongProse(probs, path+".notes", l.Notes)
		}
	}

	p.validateRanksAreDense(probs, ranks)
}

// validateRanksAreDense is the check no schema can make.
//
// Ranks must run 1..N over the levels present. A gap is how a transcribed scheme
// silently loses a level: four entries ranked 1, 2, 4, and 5 read as a complete
// four-level scheme, and nothing in the rendering says the third one is missing. A run
// that starts above 1 is the same defect at the bottom of the scale.
func (p *Profile) validateRanksAreDense(probs *problems, ranks map[int]int) {
	if len(ranks) != len(p.Levels) {
		// Duplicate ranks already reported; a density check over a short set would add
		// a second error about the same defect.
		return
	}
	var missing []int
	for want := 1; want <= len(p.Levels); want++ {
		if _, ok := ranks[want]; !ok {
			missing = append(missing, want)
		}
	}
	if len(missing) == 0 {
		return
	}
	sort.Ints(missing)
	have := make([]int, 0, len(ranks))
	for r := range ranks {
		have = append(have, r)
	}
	sort.Ints(have)
	probs.add("levels", fmt.Sprintf("ranks are %v; a %d-level scheme must use 1..%d with no gaps "+
		"(missing %v)", have, len(p.Levels), len(p.Levels), missing),
		"renumber the levels so the ranks are consecutive from 1. A gap is how a transcribed scheme "+
			"silently loses a level: four entries ranked 1, 2, 4, 5 read as a complete four-level "+
			"scheme, and nothing in the rendering says the third one is missing")
}

// validateLevelExamples bounds the reading aid.
//
// Examples are the field most likely to grow into something dangerous, in the same way
// an obligation profile's `applicability.hints` is: a match language arrives one
// plausible entry at a time. They are capped, deduped, and — by a test rather than here,
// because it is a property over the shipped set — refused if they contain predicate
// syntax.
func (p *Profile) validateLevelExamples(probs *problems, path string, l *Level) {
	if l.Examples != nil && len(l.Examples) == 0 {
		probs.add(path+".examples", "is present but empty",
			"omit the field where the source gives no examples. Unlike a control list, an empty "+
				"examples array says nothing an absent one does not")
		return
	}
	if len(l.Examples) > maxExamples {
		probs.add(path+".examples", fmt.Sprintf("has %d entries; the cap is %d",
			len(l.Examples), maxExamples),
			"the cap keeps this a list someone reads rather than a rule set something walks. Examples "+
				"are a reading aid for a person: presence of one does not establish a level and "+
				"absence does not rule one out")
	}
	seen := make(map[string]int, len(l.Examples))
	for i, ex := range l.Examples {
		ipath := fmt.Sprintf("%s.examples[%d]", path, i)
		checkProse(probs, ipath, ex, true, "state the example as the source states it")
		if prev, dup := seen[ex]; dup {
			probs.add(ipath, fmt.Sprintf("duplicates %s.examples[%d]", path, prev),
				"list each example once")
		} else {
			seen[ex] = i
		}
	}
}

// validateLevelControls checks what the policy requires at a level.
//
// The empty-list refusal is the "where the source is silent, the profile is silent" rule
// stated as a shape: a level with no published controls has NO controls array. An empty
// one is a claim that the source was consulted and stated nothing, rendered identically
// to a level nobody transcribed — and since the two are indistinguishable to a reader,
// the document may only carry the form that is unambiguous.
func (p *Profile) validateLevelControls(probs *problems, path string, l *Level) {
	if l.Controls != nil && len(l.Controls) == 0 {
		probs.add(path+".controls", "is present but empty",
			"omit the field where the source states no controls at this level. An empty array and an "+
				"absent one render identically to a reader, so only the unambiguous form is admitted; "+
				"where the source is silent, the profile is silent")
		return
	}
	if len(l.Controls) > maxControls {
		probs.add(path+".controls", fmt.Sprintf("has %d entries; the schema permits %d",
			len(l.Controls), maxControls), "")
	}
	seen := make(map[string]int, len(l.Controls))
	for i := range l.Controls {
		c := &l.Controls[i]
		cpath := fmt.Sprintf("%s.controls[%d]", path, i)
		switch {
		case c.ID == "":
			probs.add(cpath+".id", "missing",
				"give the requirement a stable id within this profile. automat's own handle, not an "+
					"institutional identifier — most published classification policies number "+
					"nothing, and inventing an official-looking identifier would be the same error as "+
					"inventing a control")
		case !reSlug.MatchString(c.ID):
			probs.add(cpath+".id", fmt.Sprintf("%s is not a control id", safe(c.ID)),
				"use 2-64 characters of lowercase letters, digits, and hyphens")
		}
		if prev, dup := seen[c.ID]; dup && c.ID != "" {
			probs.add(cpath+".id", fmt.Sprintf("duplicates %s.controls[%d].id", path, prev),
				"one entry per requirement at a level")
		} else if c.ID != "" {
			seen[c.ID] = i
		}
		checkProse(probs, cpath+".title", c.Title, true, "give the requirement a short title")
		if c.Requirement == "" {
			probs.add(cpath+".requirement", "missing",
				"state what is required, in the source's terms")
		} else {
			checkLongProse(probs, cpath+".requirement", c.Requirement)
		}
		c.Citation.validate(probs, cpath+".citation")
		if c.AppliesTo != "" {
			checkProse(probs, cpath+".applies_to", c.AppliesTo, false, "")
		}
		if c.AutomatEnforces != "" && !knownEnforcement(c.AutomatEnforces) {
			probs.add(cpath+".automat_enforces",
				fmt.Sprintf("%s is not a permitted value", safe(string(c.AutomatEnforces))),
				"use one of: "+joinEnforcement()+", or omit the field, which means no. Most entries "+
					"are no: institutional standards are written about endpoints, patch cadence, and "+
					"training, and a document implying automat delivered them would be claiming "+
					"coverage it does not have")
		}
		if c.Notes != "" {
			checkLongProse(probs, cpath+".notes", c.Notes)
		}
	}
}

// validateLevelObligations checks the routing relation.
//
// Both const-pinned fields are checked, and the reason is the same for each: an
// institutional scheme naming a regime is not automat concluding that the regime applies
// to this operator. The operator declares which obligation profiles apply, which is the
// obligation profile's own `applicability` rule stated from the other side.
func (p *Profile) validateLevelObligations(probs *problems, path string, l *Level) {
	if l.ExternalObligations != nil && len(l.ExternalObligations) == 0 {
		probs.add(path+".external_obligations", "is present but empty",
			"omit the field where the source routes to no external regime at this level")
		return
	}
	if len(l.ExternalObligations) > maxExternal {
		probs.add(path+".external_obligations", fmt.Sprintf("has %d entries; the schema permits %d",
			len(l.ExternalObligations), maxExternal), "")
	}
	seen := make(map[string]int, len(l.ExternalObligations))
	for i := range l.ExternalObligations {
		o := &l.ExternalObligations[i]
		opath := fmt.Sprintf("%s.external_obligations[%d]", path, i)
		checkProse(probs, opath+".name", o.Name, true,
			"name the regime as the source names it — \"PCI DSS\", \"HIPAA\", \"export controls\"")
		if prev, dup := seen[o.Name]; dup && o.Name != "" {
			probs.add(opath+".name", fmt.Sprintf("duplicates %s.external_obligations[%d].name",
				path, prev), "one entry per regime at a level")
		} else if o.Name != "" {
			seen[o.Name] = i
		}
		if o.ObligationProfileID != "" && !reSlug.MatchString(o.ObligationProfileID) {
			probs.add(opath+".obligation_profile_id",
				fmt.Sprintf("%s is not an obligation profile id", safe(o.ObligationProfileID)),
				"use the lowercase-and-hyphens form the shipped profiles use, e.g. dfars-7012, or "+
					"omit the field. Omitting it is the normal case and does not weaken the entry: the "+
					"institution named the regime either way, and an id naming no document is a claim "+
					"about a document nobody has read")
		}
		if o.Relation != RelationInformational {
			probs.add(opath+".relation", fmt.Sprintf("%s is not the relation", safe(string(o.Relation))),
				"the only relation is "+string(RelationInformational)+". A reference is informational: "+
					"there is no composing relation, and adding one would be adding automatic "+
					"composition under a different name")
		}
		if !o.DeclaredByOperator {
			probs.add(opath+".declared_by_operator", "is false",
				"set it to true. The operator declares which obligations apply; a classification level "+
					"mentioning a regime does not make that regime apply, and automat must never "+
					"conclude that it does")
		}
		o.Citation.validate(probs, opath+".citation")
		if o.Note != "" {
			checkLongProse(probs, opath+".note", o.Note)
		}
	}
}

// validate checks the composition block.
//
// The rule is const-pinned, and that is a design statement rather than a formality: a
// second composition rule would mean this document type models a lattice with two joins,
// which is not a lattice. Adding one is a schema version event with a review, not a new
// enum member.
func (c *Composition) validate(p *problems) {
	const path = "composition"
	if c.Rule != RuleHighestWaterMark {
		p.add(path+".rule", fmt.Sprintf("%s is not the composition rule", safe(string(c.Rule))),
			"the only rule is "+string(RuleHighestWaterMark)+", which every published scheme in the "+
				"six-institution sample shares. It is DESIGN §9's union law on a different lattice — "+
				"union of controls, intersection of permitted behavior, join of classification levels "+
				"— so a second rule here would mean a lattice with two joins, which is not a lattice")
	}
	if c.Statement == "" {
		p.add(path+".statement", "missing",
			"quote or closely paraphrase the rule as the SOURCE states it, so a reader can see automat "+
				"did not supply it. A composition rule attributed to an institution that never stated "+
				"one is automat's belief wearing the institution's name")
	} else {
		checkLongProse(p, path+".statement", c.Statement)
	}
	c.Citation.validate(p, path+".citation")
	if oc := c.OverClassification; oc != nil {
		if oc.Citation != nil {
			oc.Citation.validate(p, path+".over_classification.citation")
		}
		if oc.Note != "" {
			checkLongProse(p, path+".over_classification.note", oc.Note)
		}
	}
}

// validateInherits checks the same-issuer rule.
//
// An overlay of another institution's scheme is not an overlay: it is an assertion about
// somebody else's policy, made in a document attributed to the first institution.
func (p *Profile) validateInherits(probs *problems) {
	in := p.Inherits
	if in == nil {
		return
	}
	const path = "inherits"
	switch {
	case in.ProfileID == "":
		probs.add(path+".profile_id", "missing", "name the profile this one is layered over")
	case !reSlug.MatchString(in.ProfileID):
		probs.add(path+".profile_id", fmt.Sprintf("%s is not a profile id", safe(in.ProfileID)),
			"use 2-64 characters of lowercase letters, digits, and hyphens")
	}
	if in.ProfileID == p.Meta.ID && in.ProfileID != "" {
		probs.add(path+".profile_id", "names this profile",
			"a profile cannot inherit from itself; name the other document")
	}
	switch {
	case in.IssuerID == "":
		probs.add(path+".issuer_id", "missing",
			"name the issuer of the inherited profile — it must be this profile's own issuer")
	case !reSlug.MatchString(in.IssuerID):
		probs.add(path+".issuer_id", fmt.Sprintf("%s is not an issuer id", safe(in.IssuerID)),
			"use 2-64 characters of lowercase letters, digits, and hyphens")
	case in.IssuerID != p.Issuer.ID:
		probs.add(path+".issuer_id", fmt.Sprintf("is %s but this profile's issuer is %s",
			safe(in.IssuerID), safe(p.Issuer.ID)),
			"inheritance is within one issuer. An overlay of ANOTHER institution's scheme is not an "+
				"overlay: it is an assertion about somebody else's policy, made in a document "+
				"attributed to this one. Harvard's enterprise policy and research overlay are the "+
				"case this field exists for, and both are Harvard's")
	}
	if !knownInheritanceRelation(in.Relation) {
		probs.add(path+".relation", fmt.Sprintf("%s is not an inheritance relation",
			safe(string(in.Relation))),
			"use one of: "+joinInheritanceRelations()+". Neither composes anything: inheriting "+
				"records that a reader of this profile needs the other one too")
	}
	if in.Note != "" {
		checkLongProse(probs, path+".note", in.Note)
	}
	if in.Citation != nil {
		in.Citation.validate(probs, path+".citation")
	}
}

func (p *Profile) validateUnmodeledAxes(probs *problems) {
	if p.UnmodeledAxes != nil && len(p.UnmodeledAxes) == 0 {
		probs.add("unmodeled_axes", "is present but empty",
			"omit the field where the source defines only the axis this profile models")
		return
	}
	if len(p.UnmodeledAxes) > maxAxes {
		probs.add("unmodeled_axes", fmt.Sprintf("has %d entries; the schema permits %d",
			len(p.UnmodeledAxes), maxAxes), "")
	}
	seen := make(map[string]int, len(p.UnmodeledAxes))
	for i := range p.UnmodeledAxes {
		a := &p.UnmodeledAxes[i]
		path := fmt.Sprintf("unmodeled_axes[%d]", i)
		checkProse(probs, path+".name", a.Name, true, "name the axis as the source names it")
		if prev, dup := seen[a.Name]; dup && a.Name != "" {
			probs.add(path+".name", fmt.Sprintf("duplicates unmodeled_axes[%d].name", prev), "")
		} else if a.Name != "" {
			seen[a.Name] = i
		}
		if a.Statement == "" {
			probs.add(path+".statement", "missing",
				"say what the axis is and why this profile does not model it. The disclosure is the "+
					"whole point of the field: a profile that simply omitted an axis the source "+
					"defines would read to someone who knows the policy as an incomplete "+
					"transcription, and to someone who does not as though the institution had one axis")
		} else {
			checkLongProse(probs, path+".statement", a.Statement)
		}
		a.Citation.validate(probs, path+".citation")
	}
}

// validateCitations checks the documents this profile reads.
//
// The date_basis pairing is the interesting half. Institutional policy is published in
// two forms that differ exactly here: a versioned standard carries an approval date,
// while a living web page carries nothing at all. `retrieved-only` exists so that a
// dateless source is recorded as dateless, and an effective date supplied alongside it
// is refused rather than ignored — a date invented for a living page would be automat's
// own fabrication sitting in the field a reader checks for staleness.
func (p *Profile) validateCitations(probs *problems) {
	if len(p.Citations) == 0 {
		probs.add("citations", "empty",
			"name at least one published document this profile reads. A classification profile with "+
				"no citation is a scheme attributed to an institution on no evidence")
		return
	}
	seen := make(map[string]int, len(p.Citations))
	for i := range p.Citations {
		c := &p.Citations[i]
		path := fmt.Sprintf("citations[%d]", i)
		checkProse(probs, path+".id", c.ID, true,
			"give the document's own published identifier where it has one, e.g. \"SC-0002\". The "+
				"institution's designation, not automat's")
		checkProse(probs, path+".title", c.Title, true, "give the document's title as published")
		if prev, dup := seen[c.ID]; dup && c.ID != "" {
			probs.add(path+".id", fmt.Sprintf("duplicates citations[%d].id", prev),
				"one entry per document")
		} else if c.ID != "" {
			seen[c.ID] = i
		}

		if !knownDateBasis(c.DateBasis) {
			probs.add(path+".date_basis", fmt.Sprintf("%s is not a date basis", safe(string(c.DateBasis))),
				"use one of: "+joinDateBases()+". The field exists because institutional policy is "+
					"published both as a versioned standard carrying an approval date and as a living "+
					"web page carrying none, and the second must be recordable as dateless")
		} else if c.DateBasis == DateRetrievedOnly {
			if c.EffectiveDate != "" {
				probs.add(path+".effective_date",
					fmt.Sprintf("is %s on a retrieved-only citation", safe(c.EffectiveDate)),
					"remove it, or change date_basis. A living page bearing no date has no effective "+
						"date to state, and one supplied here would be automat's own fabrication "+
						"sitting in the field a reader checks for staleness — the retrieval timestamp "+
						"in sources[] is the fact that is actually available")
			}
			if c.SourceID == "" {
				probs.add(path+".source_id", "missing on a retrieved-only citation",
					"name the sources[] entry holding the retrieved bytes. Required for this basis "+
						"specifically: with no published date, the retrieval timestamp and hash are "+
						"the only dating the citation has, and both live in sources[]")
			}
		} else if c.DateBasis == DateNotRetrieved {
			if c.EffectiveDate != "" {
				probs.add(path+".effective_date",
					fmt.Sprintf("is %s on a not-retrieved citation", safe(c.EffectiveDate)),
					"remove it, or change date_basis. Automat has not read this document, so it has no "+
						"date to report — one supplied here would claim a reading that never happened")
			}
			if c.SourceID != "" {
				probs.add(path+".source_id",
					fmt.Sprintf("is %s on a not-retrieved citation", safe(c.SourceID)),
					"remove it, or change date_basis. There are no retrieved bytes for this citation to "+
						"point at — naming a source here, even the correct parent document, asserts that "+
						"bytes were read when none were. If a different document actually WAS retrieved "+
						"and this one is a related reference within it, cite that document instead and "+
						"use its own source_id")
			}
		} else {
			switch {
			case c.EffectiveDate == "":
				probs.add(path+".effective_date", "missing",
					"give the date the document states, as YYYY-MM-DD; or set date_basis to "+
						string(DateRetrievedOnly)+" if it states none")
			case !reDate.MatchString(c.EffectiveDate):
				probs.add(path+".effective_date",
					fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(c.EffectiveDate)), "")
			}
		}

		if c.SourceID != "" && !reSlug.MatchString(c.SourceID) {
			probs.add(path+".source_id", fmt.Sprintf("%s is not a source id", safe(c.SourceID)),
				"use the lowercase-and-hyphens form the sources[] ids use")
		}
		if c.URI != "" {
			checkProse(probs, path+".uri", c.URI, false, "")
		}
		if c.Role != "" && !knownCiteRole(c.Role) {
			probs.add(path+".role", fmt.Sprintf("%s is not a citation role", safe(string(c.Role))),
				"use one of: "+joinCiteRoles())
		}
		if c.Note != "" {
			checkLongProse(probs, path+".note", c.Note)
		}
	}
}

// validate checks one pointer into a hashed source.
//
// Whether SourceID resolves is checked separately, in validateCitationRefsResolve, which
// has the source list; this checks the shape.
func (r *CitationRef) validate(p *problems, path string) {
	switch {
	case r.SourceID == "":
		p.add(path+".source_id", "missing",
			"name the sources[] entry this claim comes from. Every claim in a derived profile traces "+
				"to a cited section of a hashed source: an unverifiable claim renders exactly as "+
				"confidently as a verified one, which is why the citation is a required field rather "+
				"than a good practice")
	case !reSlug.MatchString(r.SourceID):
		p.add(path+".source_id", fmt.Sprintf("%s is not a source id", safe(r.SourceID)),
			"use the lowercase-and-hyphens form the sources[] ids use")
	}
	checkProse(p, path+".section", r.Section, true,
		"say where in the source, as the source labels it plus enough locator to find it — "+
			"\"Section 3.1 Protection Levels (page 4)\", \"Minimum Security Standards: Servers, "+
			"Two-Step Authentication row\". A citation to a whole document is one a reader cannot check")
	if r.Quote != "" {
		checkLongProse(p, path+".quote", r.Quote)
	}
}

// validateCitationRefsResolve is the check that makes "traces to a cited section" mean
// something.
//
// A CitationRef names a source id; without this, it could name any id at all, and a
// profile whose every control cited `made-up-source` would validate perfectly while
// tracing to nothing. The schema cannot resolve a reference against a sibling array, so
// this is Go-side and enumerates every reference site — a new one added without a line
// here is a claim whose provenance nobody checks.
func (p *Profile) validateCitationRefsResolve(probs *problems) {
	known := make(map[string]bool, len(p.Sources))
	for _, s := range p.Sources {
		if s.ID != "" {
			known[s.ID] = true
		}
	}
	if len(known) == 0 {
		// validateSources already reported; resolving against an empty set would add one
		// error per citation about the same defect.
		return
	}
	ids := make([]string, 0, len(known))
	for id := range known {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	check := func(path, sourceID string) {
		if sourceID == "" || known[sourceID] {
			return
		}
		probs.add(path+".source_id", fmt.Sprintf("%s names no entry in sources[]", safe(sourceID)),
			fmt.Sprintf("the ids this document hashes are: %s. A citation naming a source the "+
				"document does not carry traces to nothing — and it renders exactly as confidently "+
				"as one that traces to bytes somebody can check", strings.Join(ids, ", ")))
	}

	if in := p.Interpretation; in != nil {
		check("interpretation", in.SourceID)
	}
	check("determination.citation", p.Determination.Citation.SourceID)
	if ml := p.Determination.MayLower; ml != nil && ml.Citation != nil {
		check("determination.may_lower.citation", ml.Citation.SourceID)
	}
	for i := range p.Levels {
		l := &p.Levels[i]
		lpath := fmt.Sprintf("levels[%d]", i)
		check(lpath+".citation", l.Citation.SourceID)
		for j := range l.Controls {
			check(fmt.Sprintf("%s.controls[%d].citation", lpath, j), l.Controls[j].Citation.SourceID)
		}
		for j := range l.ExternalObligations {
			check(fmt.Sprintf("%s.external_obligations[%d].citation", lpath, j),
				l.ExternalObligations[j].Citation.SourceID)
		}
	}
	check("composition.citation", p.Composition.Citation.SourceID)
	if oc := p.Composition.OverClassification; oc != nil && oc.Citation != nil {
		check("composition.over_classification.citation", oc.Citation.SourceID)
	}
	if in := p.Inherits; in != nil && in.Citation != nil {
		check("inherits.citation", in.Citation.SourceID)
	}
	for i := range p.UnmodeledAxes {
		check(fmt.Sprintf("unmodeled_axes[%d].citation", i), p.UnmodeledAxes[i].Citation.SourceID)
	}
	for i := range p.Citations {
		check(fmt.Sprintf("citations[%d]", i), p.Citations[i].SourceID)
	}
}

func (p *Profile) validatePolicyCaveat(probs *problems) {
	if p.PolicyCaveat == "" {
		probs.add("policy_caveat", "missing",
			"carry docs/policy-caveat.md's paragraph in substance. Required for the reason it is "+
				"required on an obligation profile: this is a reading of published policy that an "+
				"institution acts on, so a profile that does not say what kind of claim it is making "+
				"is not a valid profile")
		return
	}
	checkLongProse(probs, "policy_caveat", p.PolicyCaveat)
}

func (p *Profile) validateSources(probs *problems) {
	if len(p.Sources) == 0 {
		probs.add("sources", "empty",
			"record every document retrieved, with its hash. A claim automat renders into a "+
				"human-facing document must trace to a hashed source, and for a derived profile that "+
				"is the entire basis of the document")
		return
	}
	seen := make(map[string]int, len(p.Sources))
	for i := range p.Sources {
		s := &p.Sources[i]
		path := fmt.Sprintf("sources[%d]", i)
		switch {
		case s.ID == "":
			probs.add(path+".id", "missing", "give the source a stable id citations can name")
		case !reSlug.MatchString(s.ID):
			probs.add(path+".id", fmt.Sprintf("%s is not a source id", safe(s.ID)),
				"use 2-64 characters of lowercase letters, digits, and hyphens")
		}
		if prev, dup := seen[s.ID]; dup && s.ID != "" {
			probs.add(path+".id", fmt.Sprintf("duplicates sources[%d].id", prev),
				"one entry per document; two entries with one id make a citation ambiguous about "+
					"which bytes it names")
		} else if s.ID != "" {
			seen[s.ID] = i
		}
		checkProse(probs, path+".title", s.Title, true, "give the document's title")
		if s.Version != "" {
			checkProse(probs, path+".version", s.Version, false, "")
		}
		switch {
		case s.RetrievedAt == "":
			probs.add(path+".retrieved_at", "missing",
				"record when the document was retrieved, as an RFC 3339 UTC timestamp "+
					"(YYYY-MM-DDTHH:MM:SSZ). Required here, unlike on an obligation profile's sources: "+
					"for a living policy web page the retrieval timestamp is frequently the ONLY "+
					"dating available, so it is what a staleness check falls back on")
		case !reStamp.MatchString(s.RetrievedAt):
			probs.add(path+".retrieved_at",
				fmt.Sprintf("%s is not an RFC 3339 UTC timestamp", safe(s.RetrievedAt)),
				"use the form 2026-08-06T18:28:53Z")
		}
		if s.URI != "" {
			checkProse(probs, path+".uri", s.URI, false, "")
		}
		if s.MediaType != "" {
			checkProse(probs, path+".media_type", s.MediaType, false, "")
		}
		if !reSHA256.MatchString(s.SHA256) {
			probs.add(path+".sha256", fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(s.SHA256)),
				"hash the bytes actually retrieved. The hash is what makes this a source rather than a "+
					"label: institutional policy pages are revised in place without a version bump, so "+
					"a reference naming only a URL has a subject that can be rewritten under it")
		}
		if s.Note != "" {
			checkLongProse(probs, path+".note", s.Note)
		}
	}
}

func (p *Profile) validateSignatures(probs *problems) {
	if len(p.Signatures) > maxSignatures {
		probs.add("signatures", fmt.Sprintf("has %d entries; the schema permits %d",
			len(p.Signatures), maxSignatures),
			"a list long enough to skim past is one nobody reads")
	}
	seen := make(map[string]int, len(p.Signatures))
	for i := range p.Signatures {
		a := &p.Signatures[i]
		path := fmt.Sprintf("signatures[%d]", i)
		a.validate(probs, path)
		// The derived-profile role restriction, which is the half of the provenance rule
		// a reader's inference makes dangerous. Checked here rather than in
		// Attestation.validate because it depends on the document's authorship.
		if p.Authorship == AuthorshipDerived && a.Role != evidence.RoleInterpretedBy &&
			knownRole(a.Role) {
			probs.add(path+".role", fmt.Sprintf("is %s on a derived interpretation",
				safe(string(a.Role))),
				"a derived profile may carry only "+string(evidence.RoleInterpretedBy)+
					" attestations. The weaker roles are the danger, not the stronger ones: "+
					"`reviewed-by` or `adopted-by` on automat's reading of an institution's policy is "+
					"one inference away from \"the institution reviewed this\", which is the single "+
					"claim a derived profile must never support — and `authored-by` on a derived "+
					"profile is simply false about the policy")
		}
		k, err := signatureKey(*a)
		if err != nil {
			continue
		}
		if prev, dup := seen[k]; dup {
			probs.add(path, fmt.Sprintf("duplicates signatures[%d]", prev),
				"an identity attesting twice in the same capacity with the same statement is one "+
					"attestation")
		} else {
			seen[k] = i
		}
	}
}

func (a *Attestation) validate(p *problems, path string) {
	if !knownRole(a.Role) {
		p.add(path+".role", fmt.Sprintf("%s is not one of the attestation roles", safe(string(a.Role))),
			"the vocabulary is closed at "+joinRoles()+". None of them means approved, certified, or "+
				"compliant, and the value of the set is that the weakest claim cannot be read as the "+
				"strongest — a reader shown one undifferentiated checkmark infers the strongest "+
				"available (DESIGN §11a)")
	}
	checkProse(p, path+".identity", a.Identity, true,
		"name who attests, as they wish to be identified — an institution, an office, an email "+
			"address, an OIDC subject")
	if a.Statement == "" {
		p.add(path+".statement", "missing",
			"state in the attester's own words what is being claimed. Required, and it is what makes "+
				"this an attestation rather than a signature: a bare signature invites the reader to "+
				"supply the claim, and they supply the strongest one available")
	} else {
		checkLongProse(p, path+".statement", a.Statement)
	}
	if !reSHA256.MatchString(a.ContentSHA256) {
		p.add(path+".content_sha256",
			fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(a.ContentSHA256)),
			"name the document hash this attestation is over. Whether it matches THIS document is a "+
				"separate check (VerifyAttestationSubjects); an attestation whose subject is implicit "+
				"is one that can be moved to a different document")
	}
	switch {
	case a.AttestedAt == "":
		p.add(path+".attested_at", "missing",
			"record when the attestation was made, as YYYY-MM-DD; an undated claim cannot be checked "+
				"for staleness, and this one ages against review_by")
	case !reDate.MatchString(a.AttestedAt):
		p.add(path+".attested_at", fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(a.AttestedAt)), "")
	}
	a.Signature.validate(p, path+".signature")
}

func (s *Signature) validate(p *problems, path string) {
	if s == nil {
		// An entry with no signature block is a perfectly good attestation. The claim is
		// the attestation and the bytes are evidence for it, never the other way round.
		return
	}
	switch s.Format {
	case FormatDetachedEd25519:
		if s.KeyID == "" {
			p.add(path+".key_id", "missing on a detached signature",
				"name which key signed. Required for this form: a detached signature nobody can locate "+
					"a key for is unverifiable, which is worse than absent because it looks verifiable")
		} else {
			checkProse(p, path+".key_id", s.KeyID, true, "")
		}
		if s.IdentityIssuer != "" {
			p.add(path+".identity_issuer", "is set on a detached signature",
				"drop it, or use the "+string(FormatOIDCBundle)+" format. An issuer is meaningful only "+
					"in the keyless model, where it is the whole of what makes the identity mean anything")
		}
	case FormatOIDCBundle:
		if s.IdentityIssuer == "" {
			p.add(path+".identity_issuer", "missing on a keyless signature",
				"name the OIDC issuer that authenticated the identity. Required for this form because "+
					"the issuer is what makes the identity mean anything: \"signed by "+
					"security@example.edu\" is a different claim depending on who vouched for that "+
					"address")
		} else {
			checkProse(p, path+".identity_issuer", s.IdentityIssuer, true, "")
		}
		if s.KeyID != "" {
			p.add(path+".key_id", "is set on a keyless signature",
				"drop it, or use the "+string(FormatDetachedEd25519)+" format; in the keyless model "+
					"the identity is bound by the issuer rather than by a key the verifier has to locate")
		}
	case "":
		p.add(path+".format", "missing", "set it to one of: "+joinFormats())
	default:
		p.add(path+".format", fmt.Sprintf("%s is not a signature format", safe(string(s.Format))),
			"use one of: "+joinFormats())
	}
	switch {
	case s.Value == "":
		p.add(path+".value", "missing",
			"give the base64 signature bytes, or remove the signature block entirely; an attestation "+
				"with no signature is still recordable, but an empty signature is not")
	case len(s.Value) > maxSigValue:
		p.add(path+".value", fmt.Sprintf("is %d bytes, over the %d-byte limit",
			len(s.Value), maxSigValue), "")
	case !reBase64.MatchString(s.Value):
		p.add(path+".value", "is not base64",
			"use standard base64 with padding; automat verifies nothing in v1, but a value that "+
				"cannot be decoded is one no future verifier could either")
	}
}

func checkProse(p *problems, path, value string, required bool, fix string) {
	switch {
	case value == "":
		if required {
			p.add(path, "missing", fix)
		}
	case len(value) > maxProse:
		p.add(path, fmt.Sprintf("is %d bytes, over the %d-byte limit", len(value), maxProse),
			"state it in one line; the full text belongs in a document this one references")
	case !reProse.MatchString(value):
		p.add(path, "contains a control character",
			"use printable single-line text. These strings are rendered into reports and tables, "+
				"including whatever states what an account is rated for, where a newline forges a row")
	}
}

func checkLongProse(p *problems, path, value string) {
	switch {
	case len(value) > maxLongProse:
		p.add(path, fmt.Sprintf("is %d bytes, over the %d-byte limit", len(value), maxLongProse), "")
	case !reLongProse.MatchString(value):
		p.add(path, "contains a control character other than a newline or tab",
			"newlines and tabs are fine here; an escape byte is not, because it can hide or recolor "+
				"lines of a report a reviewer believes they have read")
	}
}

func knownRole(r evidence.Role) bool {
	for _, v := range evidence.AllRoles {
		if v == r {
			return true
		}
	}
	return false
}

func knownStatus(s Status) bool {
	for _, v := range AllStatuses {
		if v == s {
			return true
		}
	}
	return false
}

func knownAuthorship(a Authorship) bool {
	for _, v := range AllAuthorship {
		if v == a {
			return true
		}
	}
	return false
}

func knownMaintenance(m Maintenance) bool {
	for _, v := range AllMaintenance {
		if v == m {
			return true
		}
	}
	return false
}

func knownPermission(x Permission) bool {
	for _, v := range AllPermissions {
		if v == x {
			return true
		}
	}
	return false
}

func knownLowerPermission(x LowerPermission) bool {
	for _, v := range AllLowerPermissions {
		if v == x {
			return true
		}
	}
	return false
}

func knownEnforcement(e Enforcement) bool {
	for _, v := range AllEnforcement {
		if v == e {
			return true
		}
	}
	return false
}

func knownDateBasis(d DateBasis) bool {
	for _, v := range AllDateBases {
		if v == d {
			return true
		}
	}
	return false
}

func knownCiteRole(r CiteRole) bool {
	for _, v := range AllCiteRoles {
		if v == r {
			return true
		}
	}
	return false
}

func knownInheritanceRelation(r InheritanceRelation) bool {
	for _, v := range AllInheritanceRelations {
		if v == r {
			return true
		}
	}
	return false
}

func joinRoles() string {
	out := make([]string, len(evidence.AllRoles))
	for i, r := range evidence.AllRoles {
		out[i] = string(r)
	}
	return strings.Join(out, ", ")
}

func joinFormats() string {
	out := make([]string, len(AllSignatureFormats))
	for i, f := range AllSignatureFormats {
		out[i] = string(f)
	}
	return strings.Join(out, ", ")
}

func joinStatuses() string {
	out := make([]string, len(AllStatuses))
	for i, s := range AllStatuses {
		out[i] = string(s)
	}
	return strings.Join(out, ", ")
}

func joinAuthorship() string {
	out := make([]string, len(AllAuthorship))
	for i, a := range AllAuthorship {
		out[i] = string(a)
	}
	return strings.Join(out, ", ")
}

func joinMaintenance() string {
	out := make([]string, len(AllMaintenance))
	for i, m := range AllMaintenance {
		out[i] = string(m)
	}
	return strings.Join(out, ", ")
}

func joinPermissions() string {
	out := make([]string, len(AllPermissions))
	for i, x := range AllPermissions {
		out[i] = string(x)
	}
	return strings.Join(out, ", ")
}

func joinLowerPermissions() string {
	out := make([]string, len(AllLowerPermissions))
	for i, x := range AllLowerPermissions {
		out[i] = string(x)
	}
	return strings.Join(out, ", ")
}

func joinEnforcement() string {
	out := make([]string, len(AllEnforcement))
	for i, e := range AllEnforcement {
		out[i] = string(e)
	}
	return strings.Join(out, ", ")
}

func joinDateBases() string {
	out := make([]string, len(AllDateBases))
	for i, d := range AllDateBases {
		out[i] = string(d)
	}
	return strings.Join(out, ", ")
}

func joinCiteRoles() string {
	out := make([]string, len(AllCiteRoles))
	for i, r := range AllCiteRoles {
		out[i] = string(r)
	}
	return strings.Join(out, ", ")
}

func joinInheritanceRelations() string {
	out := make([]string, len(AllInheritanceRelations))
	for i, r := range AllInheritanceRelations {
		out[i] = string(r)
	}
	return strings.Join(out, ", ")
}
