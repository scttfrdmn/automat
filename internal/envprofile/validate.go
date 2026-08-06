// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

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
// The same shape as artifact.Problem and evidence.Problem, and for the same reason
// (CLAUDE.md rule 7): Path says where, Message says what is wrong, Fix says what to
// change. A validation failure an operator cannot act on is a bug in the validator.
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
//
// Reports all problems rather than stopping at the first, because an operator whose
// environment profile will not load wants the whole list, not one line per run.
type ValidationError struct {
	Subject  string
	Problems []Problem
}

func (v *ValidationError) Error() string {
	var sb strings.Builder
	subject := v.Subject
	if subject == "" {
		subject = "environment profile"
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

type problems struct{ list []Problem }

func (p *problems) add(path, message, fix string) {
	p.list = append(p.list, Problem{Path: path, Message: message, Fix: fix})
}

// safe renders an untrusted string for inclusion in an error message.
//
// An environment profile is attacker-controlled input in the threat model — an
// operator may have received one from a central IT office or forked an example — and
// this validator's output is a multi-line bulleted list. A value containing a newline
// could forge additional lines of that list, and an ANSI escape could hide or
// recolor real ones, so a reviewer reads a clean report while the document is
// anything but. %q escapes newlines, control characters, and escape bytes, and marks
// the value as data rather than structure. Same defect and same fix as AUDIT-0's M1.
func safe(s string) string {
	const max = 120
	if len(s) > max {
		return fmt.Sprintf("%q (truncated from %d bytes)", s[:max], len(s))
	}
	return fmt.Sprintf("%q", s)
}

// Patterns mirror schema/environment-profile-v1.schema.json. The schema conformance
// test is what keeps them in step.
var (
	reSemver  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reDate    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	reRegion  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	reOUID    = regexp.MustCompile(`^(ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|r-[0-9a-z]{4,32})$`)
	reBucket  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	reIAMName = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	reEmail   = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
	reBase64  = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	// Round-trip fields (CLAUDE.md rule 8): values automat WRITES that a person
	// reads back and types onto a command line. Not injection prevention — argument
	// construction is the CLI's problem — but a refusal to record a value whose
	// purpose is to travel through human hands into a shell.
	//
	// reSlug covers the environment profile id, the control set ids, and the
	// obligation profile ids. All three are typed: `--environment-profile`'s
	// document is found by id in a directory, `compile` takes control set ids as
	// arguments, and `assess --profile <id>` takes an obligation id. The id also
	// becomes part of account tags and SCP names.
	reSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	// reOUName is the OU-name charset AWS documents, minus a leading or trailing
	// space. Space is permitted inside: "Research CUI" is what an operator actually
	// names an OU, and refusing it would push them to a name they then mistype.
	reOUName = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-][A-Za-z0-9 +=,.@_-]{0,126}[A-Za-z0-9+=,.@_-]$|^[A-Za-z0-9+=,.@_-]$`)
	// reLocalDir is a relative, contained path. The `..` refusal is a separate
	// check rather than part of this expression, because Go's regexp has no
	// lookahead — the schema states it the same way, as a sibling `not`, since a
	// bound one layer cannot express is one neither layer should claim.
	reLocalDir = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]*$`)
	reTagKey   = regexp.MustCompile(`^[A-Za-z0-9 +=,.@_:/-]+$`)
	reTagValue = regexp.MustCompile(`^[A-Za-z0-9 +=,.@_:/-]*$`)
	// Prose fields are rendered into reports, tables, and the birth certificate
	// `vend` prints. A control byte in one forges a line of that output, so it is
	// refused here rather than escaped at each render site.
	reProse = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
	// long_prose permits newlines and tabs — a determination's basis is a paragraph
	// — but no other control byte.
	reLongProse = regexp.MustCompile(`^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$`)
	// reService is the service-namespace charset.
	reService = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
)

// Limits mirroring the schema's maxLength and maxItems.
const (
	maxProse         = 512
	maxLongProse     = 8192
	maxSignatures    = 16
	maxObligations   = 8
	maxSigValue      = 16384
	maxLocalDirBytes = 512
	maxTagKeyBytes   = 128
	maxTagValueBytes = 256
	maxTags          = 48
	maxEmailBytes    = 254
	// AutomatTagPrefix is reserved in both directions: baseline-protection SCPs read
	// these keys in conditions, so an operator-writable key at the same scope is a
	// forgeable one (AUDIT-1's C1).
	AutomatTagPrefix = "automat:"
)

// Validate checks the profile against every constraint the schema expresses plus the
// within-document ones it cannot, returning a *ValidationError listing all of them.
//
// It does NOT check the two cross-document facts, which need inputs Validate does not
// have: see CheckObligations for the revision-determination pairing and
// VerifyAttestationSubjects for whether each attestation names this document's hash.
// Both are separate calls precisely so that neither is silently skipped by a caller
// that only wanted a syntax check — a validator that quietly did less than its name
// suggests is the shape of gap this project's tests exist to close.
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
			"this build understands environment-profile schema "+majorOf(SchemaVersion)+
				".x; upgrade automat or update the profile")
	}

	p.Meta.validate(&probs)
	p.validateReviewBy(&probs)
	p.validateControlSets(&probs)
	p.Permitted.validate(&probs)
	p.validateObligations(&probs)
	p.Placement.validate(&probs)
	p.Account.validate(&probs)
	p.Baseline.validate(&probs)
	p.validateSignatures(&probs)

	if len(probs.list) == 0 {
		return nil
	}
	return &ValidationError{Subject: p.subject(), Problems: probs.list}
}

func (p *Profile) subject() string {
	if p.Meta.ID == "" {
		return "environment profile"
	}
	return "environment profile " + safe(p.Meta.ID)
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
		p.add("environment_profile.id", "missing",
			"give the profile a stable id, e.g. \"research-cui\"")
	case !reSlug.MatchString(m.ID):
		p.add("environment_profile.id", fmt.Sprintf("%s is not a valid id", safe(m.ID)),
			"use 2-64 characters of lowercase letters, digits, and hyphens, starting and ending "+
				"alphanumeric. The id is a round-trip value: it goes into account tags, SCP names, and "+
				"evidence records, and an operator reads it back and types it")
	}
	checkProse(p, "environment_profile.title", m.Title, true,
		"give the profile a human-readable title")
	if m.Description != "" {
		checkLongProse(p, "environment_profile.description", m.Description)
	}
}

func (p *Profile) validateReviewBy(probs *problems) {
	switch {
	case p.ReviewBy == "":
		probs.add("review_by", "missing",
			"set the date by which this profile must be re-read against the posture it deploys, as "+
				"YYYY-MM-DD. Required with no default: left alone, a profile keeps vending a posture "+
				"someone approved once, and every account it produces looks as current as the day it "+
				"was written")
	case !reDate.MatchString(p.ReviewBy):
		probs.add("review_by", fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(p.ReviewBy)),
			"a review date is a policy fact, not an event time; use the plain date form")
	}
}

func (p *Profile) validateControlSets(probs *problems) {
	if len(p.ControlSets) == 0 {
		probs.add("control_sets", "empty",
			"name at least one control set to compile; a profile compiling nothing enforces nothing, "+
				"and `vend` would produce an account whose birth certificate makes no claim")
		return
	}
	seen := make(map[string]int, len(p.ControlSets))
	for i, id := range p.ControlSets {
		path := fmt.Sprintf("control_sets[%d]", i)
		if !reSlug.MatchString(id) {
			probs.add(path, fmt.Sprintf("%s is not a control set id", safe(id)),
				"use the lowercase-and-hyphens form catalogs use, e.g. cmmc-l1 or 800-171r2. This is a "+
					"round-trip value: an operator passes it to `compile` on a command line")
		}
		if prev, dup := seen[id]; dup {
			probs.add(path, fmt.Sprintf("duplicates control_sets[%d]", prev),
				"list each control set once; compiling one twice is the same union and makes the list "+
					"disagree with itself about how many control sets an account was vended under")
		} else {
			seen[id] = i
		}
	}
}

// validate checks the permitted-behavior boundary.
//
// The empty-set guard is the load-bearing part, and it is a hard error rather than a
// warning: an empty allowlist denies every call in the account, including automat's
// own baseline, and it would be discovered AFTER create and move had succeeded. That
// is a bricked account produced by a document that looked stricter than the
// alternative (AUDIT-0's H5).
func (perm *Permitted) validate(p *problems) {
	if perm == nil {
		return
	}
	checkAllowSet(p, "permitted.regions", perm.Regions, reRegion, "region code",
		"use codes like us-east-1 or eu-west-2")
	checkAllowSet(p, "permitted.services", perm.Services, reService, "service namespace",
		"use IAM service namespaces like s3, ec2, or batch. The globally addressed services do not "+
			"belong here: they are spared by the control artifact's own region_deny_exempt_services, "+
			"which is catalog data because getting it wrong bricks an account")
}

func checkAllowSet(p *problems, path string, members []string, re *regexp.Regexp, kind, fix string) {
	if members == nil {
		return
	}
	if len(members) < MinPermittedMembers {
		p.add(path, "is present but empty",
			"omit the field to add no boundary on this axis, or list at least one member. An empty "+
				"allowlist is not a strict policy but a DENY-ALL: it denies every call in the account, "+
				"including the ones automat's own baseline makes, and nothing about the document says so")
		return
	}
	seen := make(map[string]int, len(members))
	for i, v := range members {
		ipath := fmt.Sprintf("%s[%d]", path, i)
		if !re.MatchString(v) {
			p.add(ipath, fmt.Sprintf("%s is not a %s", safe(v), kind), fix)
		}
		if prev, dup := seen[v]; dup {
			p.add(ipath, fmt.Sprintf("duplicates %s[%d]", path, prev),
				"list each member once; a repeated entry permits nothing extra and makes the set "+
					"disagree with itself about how many are permitted")
		} else {
			seen[v] = i
		}
	}
}

func (p *Profile) validateObligations(probs *problems) {
	if p.Obligations == nil {
		return
	}
	if len(p.Obligations) == 0 {
		probs.add("obligations", "is present but empty",
			"omit the field, or name at least one obligation profile. An empty list and an absent one "+
				"read the same to a person and differently to a schema, which is the ambiguity worth "+
				"refusing in a document an auditor reads")
		return
	}
	if len(p.Obligations) > maxObligations {
		probs.add("obligations", fmt.Sprintf("has %d entries; the schema permits %d",
			len(p.Obligations), maxObligations),
			"an environment built to satisfy more than a handful of obligations at once is one whose "+
				"scope nobody can state; split it")
	}
	seen := make(map[string]int, len(p.Obligations))
	for i := range p.Obligations {
		o := &p.Obligations[i]
		path := fmt.Sprintf("obligations[%d]", i)
		switch {
		case o.ID == "":
			probs.add(path+".id", "missing",
				"name the obligation profile, e.g. cmmc-l1, dfars-7012, or nih-cadr-dua")
		case !reSlug.MatchString(o.ID):
			probs.add(path+".id", fmt.Sprintf("%s is not an obligation profile id", safe(o.ID)),
				"use the lowercase-and-hyphens form the shipped profiles use, e.g. dfars-7012. This is "+
					"a round-trip value: `assess --profile <id>` takes it on a command line")
		}
		if prev, dup := seen[o.ID]; dup && o.ID != "" {
			probs.add(path+".id", fmt.Sprintf("duplicates obligations[%d]", prev),
				"one entry per obligation profile: two entries for one obligation could carry two "+
					"different determinations, and this validator will not choose between them")
		} else if o.ID != "" {
			seen[o.ID] = i
		}
		if !reSHA256.MatchString(o.ContentSHA256) {
			probs.add(path+".content_sha256",
				fmt.Sprintf("%s is not a lowercase hex SHA-256", safe(o.ContentSHA256)),
				"hash the obligation profile you actually read. The hash is what makes this a reference "+
					"rather than a label: an obligation profile is a reading of policy that moves — "+
					"notices are superseded, phase-in dates arrive, a class deviation expires — so a "+
					"reference naming only an id has a subject that can be rewritten under it")
		}
		o.RevisionDetermination.validate(probs, path+".revision_determination")
	}
}

func (d *Determination) validate(p *problems, path string) {
	if d == nil {
		return
	}
	checkProse(p, path+".value", d.Value, true,
		"state the determination itself, e.g. the control catalog revision the instrument leaves open")
	checkProse(p, path+".determined_by", d.DeterminedBy, true,
		"name who determined it — a person, an office, or a role, as they wish to be identified. A "+
			"determination with no named determiner is an anonymous claim in a document an "+
			"institution acts on")
	switch {
	case d.DeterminedAt == "":
		p.add(path+".determined_at", "missing",
			"record when the determination was made, as YYYY-MM-DD; an undated determination cannot "+
				"be checked for staleness against review_by")
	case !reDate.MatchString(d.DeterminedAt):
		p.add(path+".determined_at", fmt.Sprintf("%s is not a YYYY-MM-DD date", safe(d.DeterminedAt)), "")
	}
	if d.Statement == "" {
		p.add(path+".statement", "missing",
			"state the basis for the determination in the determiner's own words. Required for the "+
				"reason an attestation's statement is: a bare value invites the reader to supply the "+
				"justification themselves, and they supply the strongest one available")
	} else {
		checkLongProse(p, path+".statement", d.Statement)
	}
}

func (pl *Placement) validate(p *problems) {
	switch {
	case pl.TargetOU == "":
		p.add("placement.target_ou", "missing",
			"name the OU the account is moved into after creation; new accounts always materialize "+
				"under the root (DESIGN §3, fact 4), so a placement is required")
	case !reOUID.MatchString(pl.TargetOU):
		p.add("placement.target_ou", fmt.Sprintf("%s is not an OU or root id", safe(pl.TargetOU)),
			"use an id of the form ou-abcd-11111111 or r-abcd")
	}
	if len(pl.OUPath) > MaxOUPathDepth {
		p.add("placement.ou_path", fmt.Sprintf("has %d levels, more than the %d permitted",
			len(pl.OUPath), MaxOUPathDepth),
			fmt.Sprintf("an organization permits %d levels of OU nesting under the root (DESIGN §3, "+
				"fact 10); a deeper path cannot be created and the failure would arrive after the "+
				"account already exists", MaxOUPathDepth))
	}
	for i, name := range pl.OUPath {
		ipath := fmt.Sprintf("placement.ou_path[%d]", i)
		switch {
		case name == "":
			p.add(ipath, "is empty", "name the OU, or shorten the path")
		case len(name) > 128:
			p.add(ipath, fmt.Sprintf("is %d bytes, over the 128-byte limit AWS permits", len(name)), "")
		case !reOUName.MatchString(name):
			p.add(ipath, fmt.Sprintf("%s is not a usable OU name", safe(name)),
				"use letters, digits, spaces, and +=,.@_- with no leading or trailing space. Not a "+
					"traversal defense — nothing resolves an OU name as a path — but this value is "+
					"rendered into the plan `vend` prints before it acts, and a plan whose lines can be "+
					"forged is not a plan an operator can approve")
		}
	}
	if len(pl.OUPath) > 0 && !pl.CreateIntermediateOUs {
		// A note rather than a refusal would be wrong here: the path is either
		// ensured or it is decoration, and a profile naming OUs that automat will not
		// create describes a placement that does not happen.
		p.add("placement.ou_path", "names OUs but create_intermediate_ous is false",
			"set create_intermediate_ous to true, or remove the path. As written the OUs would not be "+
				"created and the account would land in target_ou, which is not where this profile says "+
				"it goes")
	}
}

func (a *Account) validate(p *problems) {
	if a == nil {
		return
	}
	if a.EmailPattern != "" {
		validateEmailPattern(p, a.EmailPattern)
	}
	if a.RoleName != "" && !reIAMName.MatchString(a.RoleName) {
		p.add("account.role_name", fmt.Sprintf("%s is not an IAM role name", safe(a.RoleName)),
			"use up to 64 characters of letters, digits, and +=,.@_-")
	}
	switch a.IAMUserAccessToBilling {
	case "", BillingAccessAllow, BillingAccessDeny:
		// Empty means the API's own default; see the field comment.
	default:
		p.add("account.iam_user_access_to_billing",
			fmt.Sprintf("%s is not a permitted value", safe(string(a.IAMUserAccessToBilling))),
			"use ALLOW or DENY, or omit the field")
	}
	if len(a.Tags) > maxTags {
		p.add("account.tags", fmt.Sprintf("has %d entries; the schema permits %d", len(a.Tags), maxTags),
			"AWS caps tags per resource, and automat's own conventional tags are applied on top of "+
				"these; a profile at the cap would make a vend fail after the account exists")
	}
	keys := make([]string, 0, len(a.Tags))
	for k := range a.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := fmt.Sprintf("account.tags[%s]", safe(k))
		switch {
		case k == "":
			p.add("account.tags", "has an empty key", "name each tag")
		case strings.HasPrefix(k, AutomatTagPrefix):
			// The other half of AUDIT-1's C1. This is not a namespace nicety: DESIGN
			// §10's baseline-protection SCPs read automat's own tags in
			// aws:ResourceTag conditions, so a key an operator can write at the same
			// scope is a key that can be forged, and a condition that reads a
			// forgeable tag is not a condition.
			p.add(path, "uses the reserved "+AutomatTagPrefix+" prefix",
				"choose a key outside that prefix. automat's own conventional tags (DESIGN §14) are "+
					"applied automatically and are READ BY baseline-protection SCP conditions, so a tag "+
					"this document could write at the same scope would be one an account could forge to "+
					"exempt itself from its own controls")
		case len(k) > maxTagKeyBytes:
			p.add(path, fmt.Sprintf("is %d bytes, over the %d-byte limit", len(k), maxTagKeyBytes), "")
		case !reTagKey.MatchString(k):
			p.add(path, "is not a usable tag key",
				"use letters, digits, spaces, and +=,.@_:/- ; tag keys are rendered into `list` output "+
					"and the birth certificate, where a control byte forges a line")
		}
		v := a.Tags[k]
		if len(v) > maxTagValueBytes {
			p.add(path, fmt.Sprintf("has a %d-byte value, over the %d-byte limit", len(v), maxTagValueBytes), "")
		} else if !reTagValue.MatchString(v) {
			p.add(path, fmt.Sprintf("has an unusable value %s", safe(v)),
				"use letters, digits, spaces, and +=,.@_:/-")
		}
	}
}

// validateEmailPattern checks the template `vend` substitutes an account name into.
//
// The placeholder check is the part no schema can make: the schema bounds the
// alphabet, but "is there exactly one {name} in it" is a claim about structure. A
// pattern with no placeholder produces one email for every account, and the second
// vend fails on a duplicate address after the first account exists (DESIGN §3, fact
// 11) — so it is refused here rather than discovered there.
func validateEmailPattern(p *problems, pattern string) {
	const path = "account.email_pattern"
	if len(pattern) > maxEmailBytes {
		p.add(path, fmt.Sprintf("is %d bytes, over the %d-byte limit for an address",
			len(pattern), maxEmailBytes), "")
		return
	}
	if !reEmail.MatchString(strings.ReplaceAll(pattern, EmailNamePlaceholder, "x")) {
		p.add(path, fmt.Sprintf("%s is not an email template", safe(pattern)),
			"use the form research-admin+"+EmailNamePlaceholder+"@dept.edu. The value reaches "+
				"CreateAccount and is echoed into the birth certificate, the onboarding bundle, and "+
				"every error message about the vend, so the alphabet is bounded rather than "+
				"everything-but-@")
		return
	}
	switch strings.Count(pattern, EmailNamePlaceholder) {
	case 1:
		// The only useful form.
	case 0:
		p.add(path, "has no "+EmailNamePlaceholder+" placeholder",
			"include "+EmailNamePlaceholder+" where the account name goes. Every account needs a "+
				"globally unique email (DESIGN §3, fact 11), so a pattern without the placeholder "+
				"produces one address for every account and the second vend fails on a duplicate — "+
				"after the first account already exists")
	default:
		p.add(path, "has more than one "+EmailNamePlaceholder+" placeholder",
			"use the placeholder once; substituting a name twice produces an address nobody intended "+
				"and no obvious way to read back which account it belongs to")
	}
}

func (b *Baseline) validate(p *problems) {
	if b.ConfigRecorder.DeliveryBucket != "" && !reBucket.MatchString(b.ConfigRecorder.DeliveryBucket) {
		p.add("baseline.config_recorder.delivery_bucket",
			fmt.Sprintf("%s is not an S3 bucket name", safe(b.ConfigRecorder.DeliveryBucket)),
			"use 3-63 characters of lowercase letters, digits, dots, and hyphens")
	}
	if !b.ConfigRecorder.Enabled && b.ConfigRecorder.DeliveryBucket != "" {
		p.add("baseline.config_recorder.delivery_bucket", "is set but the recorder is disabled",
			"enable the recorder, or drop the bucket; as written the bucket would never be written to, "+
				"and a profile naming one reads as though the detective baseline were deployed")
	}
	b.Regions.validate(p)
	// Naming a role automat will not create is legitimate — the operator made it
	// themselves — so create:false with a name is not an error here. Whether the role
	// actually exists surfaces at pack time, against the ARN the caller supplies for
	// the SCP exemption that names it.
	if a := b.AutomationRole; a != nil && a.Name != "" && !reIAMName.MatchString(a.Name) {
		p.add("baseline.automation_role.name", fmt.Sprintf("%s is not an IAM role name", safe(a.Name)),
			"use up to 64 characters of letters, digits, and +=,.@_-")
	}
	b.Attestations.validate(p, "baseline.attestations", false)
	b.Evidence.validate(p, "baseline.evidence", true)
}

func (r *BaselineRegions) validate(p *problems) {
	if r == nil {
		return
	}
	if r.Home != "" && !reRegion.MatchString(r.Home) {
		p.add("baseline.regions.home", fmt.Sprintf("%s is not a region code", safe(r.Home)),
			"use codes like us-east-1")
	}
	for _, set := range []struct {
		path    string
		members []string
	}{
		{"baseline.regions.enable", r.Enable},
		{"baseline.regions.disable", r.Disable},
	} {
		seen := make(map[string]int, len(set.members))
		for i, v := range set.members {
			ipath := fmt.Sprintf("%s[%d]", set.path, i)
			if !reRegion.MatchString(v) {
				p.add(ipath, fmt.Sprintf("%s is not a region code", safe(v)), "use codes like us-east-1")
			}
			if prev, dup := seen[v]; dup {
				p.add(ipath, fmt.Sprintf("duplicates %s[%d]", set.path, prev), "list each region once")
			} else {
				seen[v] = i
			}
		}
	}
	// Enabling and disabling one region is not an ordering question automat gets to
	// answer. Both are Account Management API calls made in the same baseline step,
	// and whichever ran last would decide — so the document is refused instead.
	inEnable := make(map[string]bool, len(r.Enable))
	for _, v := range r.Enable {
		inEnable[v] = true
	}
	for i, v := range r.Disable {
		if inEnable[v] {
			p.add(fmt.Sprintf("baseline.regions.disable[%d]", i),
				fmt.Sprintf("%s also appears in baseline.regions.enable", safe(v)),
				"list the region in one or the other. Both are Account Management API calls in the same "+
					"baseline step, so whichever ran last would decide what the account ends up with, "+
					"and automat will not pick an order for you")
		}
	}
}

func (o *OutputTargets) validate(p *problems, path string, mirrorAllowed bool) {
	if o == nil {
		return
	}
	if o.LocalDir != "" {
		validateLocalDir(p, path+".local_dir", o.LocalDir)
	}
	for _, b := range []struct {
		path, value string
	}{
		{path + ".in_account_bucket", o.InAccountBucket},
		{path + ".management_mirror_bucket", o.ManagementMirrorBucket},
	} {
		if b.value != "" && !reBucket.MatchString(b.value) {
			p.add(b.path, fmt.Sprintf("%s is not an S3 bucket name", safe(b.value)),
				"use 3-63 characters of lowercase letters, digits, dots, and hyphens")
		}
	}
	if !mirrorAllowed && o.ManagementMirrorBucket != "" {
		p.add(path+".management_mirror_bucket", "is not a field of this block",
			"the management mirror is for evidence manifests (DESIGN §11), not attestation stubs. "+
				"Move it to baseline.evidence, or remove it; a field silently ignored here would read "+
				"to an operator as a mirror that exists")
	}
}

// validateLocalDir refuses anything but a relative, contained path.
//
// This is the one field in an environment profile naming somewhere automat WRITES,
// and the document is attacker-controlled input in the threat model: an operator may
// have received it from a central IT office or forked an example. An absolute path
// would let the profile choose the destination of every attestation stub and evidence
// manifest a vend produces.
func validateLocalDir(p *problems, path, dir string) {
	if len(dir) > maxLocalDirBytes {
		p.add(path, fmt.Sprintf("is %d bytes, over the %d-byte limit", len(dir), maxLocalDirBytes), "")
		return
	}
	const fix = "use a path relative to the working directory, e.g. \"evidence\" or " +
		"\"out/compliance\". This is the one field in a profile naming somewhere automat writes, and " +
		"a profile is a document an operator may have received rather than written — an absolute or " +
		"escaping path would let it choose where every stub and manifest a vend produces lands"
	if !reLocalDir.MatchString(dir) {
		p.add(path, fmt.Sprintf("%s is not a relative contained path", safe(dir)), fix)
		return
	}
	// Checked separately from the pattern because Go's regexp has no lookahead; the
	// schema states it as a sibling `not` for the same reason.
	for _, seg := range strings.Split(dir, "/") {
		if seg == ".." {
			p.add(path, fmt.Sprintf("%s contains a .. segment", safe(dir)), fix)
			return
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
		p.add(path+".content_sha256", fmt.Sprintf("%s is not a lowercase hex SHA-256",
			safe(a.ContentSHA256)),
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
		// An entry with no signature block is a perfectly good attestation — an
		// institution asserting authorship of a file it publishes itself. The claim is
		// the attestation and the bytes are evidence for it, never the other way
		// round.
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
				"drop it, or use the oidc-identity-bundle format. An issuer is meaningful only in the "+
					"keyless model, where it is the whole of what makes the identity mean anything")
		}
	case FormatOIDCBundle:
		if s.IdentityIssuer == "" {
			p.add(path+".identity_issuer", "missing on a keyless signature",
				"name the OIDC issuer that authenticated the identity. Required for this form because "+
					"the issuer is what makes the identity mean anything: \"signed by "+
					"security@example.edu\" is a different claim depending on who vouched for that address")
		} else {
			checkProse(p, path+".identity_issuer", s.IdentityIssuer, true, "")
		}
		if s.KeyID != "" {
			p.add(path+".key_id", "is set on a keyless signature",
				"drop it, or use the detached-ed25519 format; in the keyless model the identity is bound "+
					"by the issuer rather than by a key the verifier has to locate")
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
			"use printable single-line text. These strings are rendered into reports, tables, and the "+
				"birth certificate `vend` prints, where a newline forges a row")
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
