// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package classprofile

import "github.com/scttfrdmn/automat/internal/evidence"

// SchemaVersion is the classification-profile schema version this build emits.
const SchemaVersion = "1.0.0"

// Profile is one institutional classification profile.
//
// Named Profile inside a package named classprofile rather than
// ClassificationProfile, so callers read `classprofile.Profile` — which says which of
// the three document types it is at the use site, matching envprofile.Profile. The
// three are `envprofile.Profile`, the obligation profile (vendored data, no Go type
// yet), and this.
//
// Field order follows the schema's for MarshalIndented's readability only; the content
// hash goes through canonical form, which sorts keys.
type Profile struct {
	SchemaVersion string `json:"schema_version"`
	Meta          Meta   `json:"classification_profile"`
	// Issuer is the institution whose scheme this is — separate from Meta and, unlike
	// Meta, INSIDE the content hash. Which institution's levels these are is the whole
	// of what the document claims, so it must not be editable under an attestation that
	// still verifies.
	Issuer Issuer `json:"issuer"`
	// Status says whether the scheme is the institution's current one.
	Status Status `json:"status"`
	// ReviewBy is the date by which this profile must be re-read against the
	// institution's published policy. Required, with no default: an institutional
	// scheme moves less than a federal clause but it does move, and a profile nobody
	// re-reads keeps rating accounts under a policy that changed.
	//
	// Inside the content hash per DESIGN §11a, so extending it is a change no earlier
	// attestation vouches for.
	ReviewBy string `json:"review_by"`
	// Authorship distinguishes "UC says" from "automat's reading of what UC says".
	// See AuthorshipDerived.
	Authorship Authorship `json:"authorship"`
	// Maintenance distinguishes a document automat maintains from an example to fork.
	// Every derived profile is MaintenanceExample, enforced at both layers.
	Maintenance Maintenance `json:"maintenance"`
	// Interpretation is required exactly when Authorship is AuthorshipDerived and
	// forbidden otherwise. It carries the non-endorsement statement.
	Interpretation *Interpretation `json:"interpretation,omitempty"`
	// Signatures are optional attestations over this document's content hash.
	// PROVENANCE ONLY, and automat verifies none of them in v1.
	Signatures []Attestation `json:"signatures,omitempty"`
	// Determination names WHO DECIDES at this institution. The answer is always a
	// human role, never this tool.
	Determination Determination `json:"determination"`
	// Levels are the institution's levels. Never assume four: the published schemes
	// run three, four, and five. Order comes from Level.Rank and nowhere else.
	Levels []Level `json:"levels"`
	// Composition is the highest-water-mark rule, modeled as cited data rather than as
	// a compiled-in assumption. See Join.
	Composition Composition `json:"composition"`
	// Inherits records one profile layered over another FROM THE SAME ISSUER
	// (Harvard's enterprise policy plus research overlay). Deliberately not
	// composition: inheriting merges nothing automatically.
	Inherits *Inherits `json:"inherits,omitempty"`
	// UnmodeledAxes are axes the source defines that this profile does not model, each
	// cited. UC's separate Availability axis is why this field exists: an omission
	// that is disclosed is a different document from one that is silent.
	UnmodeledAxes []UnmodeledAxis `json:"unmodeled_axes,omitempty"`
	// Citations are the published documents this profile reads, in reading order.
	Citations []Citation `json:"citations"`
	// PolicyCaveat is docs/policy-caveat.md's paragraph, in substance. Required, and
	// asserted by test rather than trusted.
	PolicyCaveat string `json:"policy_caveat"`
	// Sources is every document retrieved, by hash. Every CitationRef.SourceID in the
	// document resolves against these.
	Sources []HashedReference `json:"sources"`
}

// Meta is the profile's identity.
type Meta struct {
	// ID is a round-trip field (CLAUDE.md rule 8): an operator reads it back and types
	// it. Patterned at both layers.
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// Issuer is the institution whose scheme this is.
type Issuer struct {
	// ID is a round-trip field (rule 8) and additionally the key Inherits.IssuerID is
	// checked against: an institution's overlay policy may only inherit from that same
	// institution's.
	ID string `json:"id"`
	// Name is the institution as it names itself. Rendered verbatim into the
	// non-endorsement statement, which Validate requires it to appear in.
	Name string `json:"name"`
	// Unit is the office or body within the institution that issued the scheme, where
	// the source names one. Absent where the source does not say.
	Unit string `json:"unit,omitempty"`
}

// Status says whether a scheme is the institution's current one.
type Status string

// The statuses. StatusSuperseded is recordable rather than deletable: an account rated
// years ago was rated under whatever was current then, and an evidence record naming a
// superseded profile is still a true record of what was believed.
const (
	StatusInForce    Status = "in-force"
	StatusProposed   Status = "proposed"
	StatusSuperseded Status = "superseded"
)

// AllStatuses is the closed set.
var AllStatuses = []Status{StatusInForce, StatusProposed, StatusSuperseded}

// Authorship says who wrote this document, which is a different question from whose
// policy it describes.
type Authorship string

// The authorship values.
const (
	// AuthorshipDerived means automat (or a third party) read the institution's
	// published policy and wrote this. The institution has reviewed and endorsed
	// nothing, Interpretation is required, and every claim must cite a hashed source.
	AuthorshipDerived Authorship = "derived-interpretation"
	// AuthorshipIssuer means the institution wrote it about its own scheme, so there
	// is no interpretation to disclose and Interpretation is forbidden.
	AuthorshipIssuer Authorship = "issuer-authored"
)

// AllAuthorship is the closed set.
var AllAuthorship = []Authorship{AuthorshipDerived, AuthorshipIssuer}

// Maintenance says whether this document is maintained as part of automat or shipped
// as an example to fork.
type Maintenance string

// The maintenance values.
const (
	// MaintenanceExample is the only admissible value for a derived profile: automat
	// is not the maintainer of an institution's classification scheme and must never
	// appear to be.
	MaintenanceExample Maintenance = "example-and-forkable"
	// MaintenanceShipped is for the documents automat genuinely does maintain.
	MaintenanceShipped Maintenance = "shipped-and-maintained"
)

// AllMaintenance is the closed set.
var AllMaintenance = []Maintenance{MaintenanceExample, MaintenanceShipped}

// Interpretation is the provenance disclosure on a derived profile.
//
// For a derived profile this is the most load-bearing block in the document: the whole
// risk of publishing a reading of someone else's policy is that the reading gets
// mistaken for the policy.
type Interpretation struct {
	// Interpreter is who produced the interpretation — the identity that would sign
	// `interpreted-by`.
	Interpreter string `json:"interpreter"`
	// SourceID is the Sources entry this profile is a reading OF: the primary
	// document, distinct from any supporting source a single control cites.
	SourceID string `json:"source_id"`
	// Attribution credits the source in the terms the source itself sets.
	Attribution string `json:"attribution"`
	// NonEndorsement is the statement ROADMAP fixes the substance of, and which
	// Validate and a test both check rather than trust:
	//
	//	This is automat's interpretation of a published policy. It was not authored,
	//	reviewed, or endorsed by <institution>. The institution's own policy governs;
	//	verify against it.
	//
	// The issuer's own name must appear in it, because a disclaimer that names no
	// institution is one a reader will attach to whichever institution they had in
	// mind. Inside the content hash, so it cannot be softened under material that
	// still verifies.
	NonEndorsement string `json:"non_endorsement"`
}

// Determination is who decides a level at this institution.
//
// Recorded because an operator rating an account has to know whose determination they
// are recording, and because naming the role is what makes the absence of a matcher a
// design rather than an omission.
type Determination struct {
	// Roles are the roles the institution's policy makes responsible — 'Proprietors',
	// 'Unit Information Security Leads'. Roles as the source names them, never
	// individuals: this is vendored data shared across institutions.
	Roles []string `json:"roles"`
	// Process is the determination process as PROSE FOR A HUMAN, in the source's own
	// terms. Prose deliberately: a process expressed as steps a machine could walk is
	// a matcher with extra words, and the point of this field is to tell an operator
	// who to go and ask.
	Process string `json:"process"`
	// AutomatDetermines is always false, and Validate requires it to be, so a reader
	// of any profile sees the rule rather than having to know it. Same device as the
	// obligation profile's `applicability.declared_by_operator: const true`, pointing
	// the other way.
	AutomatDetermines bool        `json:"automat_determines"`
	Citation          CitationRef `json:"citation"`
	MayRaise          Permission  `json:"may_raise,omitempty"`
	// MayLower is separate from MayRaise because the two are asymmetric in every
	// scheme that addresses them at all: raising is deliberate over-classification and
	// generally permitted, lowering is an exception process.
	MayLower *MayLower `json:"may_lower,omitempty"`
	Notes    string    `json:"notes,omitempty"`
}

// Permission is a three-valued answer where "the source does not say" is a distinct
// and common answer from yes or no.
type Permission string

// The permission values.
const (
	PermissionYes       Permission = "yes"
	PermissionNo        Permission = "no"
	PermissionNotStated Permission = "not-stated"
)

// AllPermissions is the closed set.
var AllPermissions = []Permission{PermissionYes, PermissionNo, PermissionNotStated}

// MayLower says whether a determiner may classify BELOW the published level.
type MayLower struct {
	Permitted LowerPermission `json:"permitted"`
	// ExceptionProcess is the named process, where the source names one — UC's is
	// "IS-3, III.2.2, Exception Process".
	ExceptionProcess string       `json:"exception_process,omitempty"`
	Citation         *CitationRef `json:"citation,omitempty"`
}

// LowerPermission is MayLower's vocabulary. Distinct from Permission because
// "only-by-exception" is the answer most published schemes actually give, and folding
// it into "yes" would read as permission where the source describes a process.
type LowerPermission string

// The lower-permission values.
const (
	LowerYes             LowerPermission = "yes"
	LowerNo              LowerPermission = "no"
	LowerOnlyByException LowerPermission = "only-by-exception"
)

// AllLowerPermissions is the closed set.
var AllLowerPermissions = []LowerPermission{LowerYes, LowerNo, LowerOnlyByException}

// Level is one level of the institution's scheme.
type Level struct {
	// ID is a round-trip field (rule 8) and the one an operator types most often — a
	// rating is recorded per account, so this value travels from a policy document
	// through automat's output and back onto a command line.
	ID string `json:"id"`
	// Label is the level as the institution writes it — "P4 - High", "High Risk",
	// "DSL 3", "Restricted". The institution's spelling rather than automat's
	// normalization: an operator comparing automat's output against their own policy
	// page is doing a string comparison by eye.
	Label string `json:"label"`
	// Rank is the level's position in the order, as an EXPLICIT INTEGER, 1 being the
	// least protective. Required, with no default and no inference.
	//
	// Label-derived ordering is the defect this field exists to make impossible: the
	// published schemes sort opposite by name. U-M's `Restricted` is the TOP of a list
	// whose names run downward, while Harvard's DSL 1-5 and UC's P1-P4 run upward, so
	// an implementation that ordered by label passes on four of six schemes and
	// silently rates an account at the wrong end of the other two.
	Rank int `json:"rank"`
	// Definition is what the level means, in the source's terms.
	Definition string      `json:"definition"`
	Citation   CitationRef `json:"citation"`
	// Examples are at most a handful of data types the SOURCE itself places at this
	// level, as a reading aid for a person. NOT a matcher, NOT exhaustive, and NOT
	// evaluated: presence of an example does not establish a level and absence does
	// not rule one out. An example automat added would be automat classifying data.
	Examples []string `json:"examples,omitempty"`
	// Controls are what the institution's policy requires at this level. Absent where
	// the source states nothing — a level with no published controls has no Controls,
	// and that silence is the honest rendering.
	Controls []Control `json:"controls,omitempty"`
	// ExternalObligations are external regimes the source ROUTES TO at this level.
	// Informational only: nothing is composed automatically.
	ExternalObligations []ExternalObligation `json:"external_obligations,omitempty"`
	Notes               string               `json:"notes,omitempty"`
}

// Control is one requirement the institution's policy states at a level.
type Control struct {
	// ID is a stable id for the requirement WITHIN this profile — automat's own
	// handle, not an institutional identifier. Most published classification policies
	// number nothing, and inventing an official-looking identifier would be the same
	// error as inventing a control.
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Requirement string      `json:"requirement"`
	Citation    CitationRef `json:"citation"`
	// AppliesTo is the asset class the source scopes the requirement to, where it
	// scopes it at all. Institutional standards are usually written per asset class,
	// and flattening them would attribute an endpoint requirement to a server.
	AppliesTo string `json:"applies_to,omitempty"`
	// AutomatEnforces says whether automat can enforce or monitor this in a vended
	// account. Defaults to EnforcesNo by being absent, and EnforcesNo is the expected
	// value for most entries: institutional standards are written about endpoints,
	// patch cadence, and training, and a document implying automat delivered them
	// would be claiming coverage it does not have.
	AutomatEnforces Enforcement `json:"automat_enforces,omitempty"`
	Notes           string      `json:"notes,omitempty"`
}

// Enforcement says whether automat can enforce or monitor a control.
type Enforcement string

// The enforcement values.
const (
	EnforcesNo        Enforcement = "no"
	EnforcesPartially Enforcement = "partially"
	EnforcesYes       Enforcement = "yes"
)

// AllEnforcement is the closed set.
var AllEnforcement = []Enforcement{EnforcesNo, EnforcesPartially, EnforcesYes}

// Enforces reports the effective value, applying the schema's absent-means-no rule.
// Present-and-no is the same claim as absent; the value exists so a profile can state
// it rather than leave a reader inferring.
func (c Control) Enforces() Enforcement {
	if c.AutomatEnforces == "" {
		return EnforcesNo
	}
	return c.AutomatEnforces
}

// ExternalObligation is one external regime an institutional level routes to.
type ExternalObligation struct {
	// Name is the regime as the SOURCE names it — "PCI DSS", "HIPAA", "export
	// controls". Prose rather than an id because the source names a regime, not an
	// automat document.
	Name string `json:"name"`
	// ObligationProfileID names the automat obligation profile implementing this
	// regime, WHERE ONE EXISTS. Absent is the normal case and does not weaken the
	// entry: the institution named the regime either way. Never invented to make a
	// reference resolvable — an id naming no document is a claim about a document
	// nobody has read.
	ObligationProfileID string `json:"obligation_profile_id,omitempty"`
	// Relation is single-valued: a reference is informational. There is no composing
	// relation, and adding one would be adding automatic composition under a
	// different name.
	Relation ObligationRelation `json:"relation"`
	// DeclaredByOperator is always true, and Validate requires it to be. The operator
	// declares which obligations apply; a classification level mentioning a regime
	// does not make that regime apply.
	DeclaredByOperator bool        `json:"declared_by_operator"`
	Citation           CitationRef `json:"citation"`
	Note               string      `json:"note,omitempty"`
}

// ObligationRelation is the relation an external-obligation reference carries.
type ObligationRelation string

// RelationInformational is the only relation. Const-pinned at both layers.
const RelationInformational ObligationRelation = "informational-reference"

// Composition is the highest-water-mark rule, as cited data.
type Composition struct {
	// Rule is single-valued on purpose. A second composition rule is not a data
	// change: it would mean this document type models a lattice with two joins, which
	// is not a lattice.
	Rule CompositionRule `json:"rule"`
	// Statement is the rule as the SOURCE states it, so a reader can see automat did
	// not supply it.
	Statement string      `json:"statement"`
	Citation  CitationRef `json:"citation"`
	// OverClassification records whether the source addresses deliberate
	// over-classification. Absent where the source is silent — automat has an opinion
	// here and it does not belong in a document attributed to an institution.
	OverClassification *OverClassification `json:"over_classification,omitempty"`
}

// CompositionRule is Composition's vocabulary.
type CompositionRule string

// RuleHighestWaterMark is the one rule every published scheme in the six-institution
// sample shares.
const RuleHighestWaterMark CompositionRule = "highest-water-mark"

// CompositionRuleAssociates records, as a sentence a reader will find at the point of
// use, why the level join is not a second algebra.
//
// DESIGN §9 states the law for control sets: union of controls, intersection of
// permitted behavior. This is the third operation under the same law — the stricter
// reading wins, so composing inputs can never relax what any single input required.
// `compile` holds idempotence, commutativity, associativity, and monotonicity as
// property tests over control sets; Join holds the same four over levels.
const CompositionRuleAssociates = "highest-water-mark composition is DESIGN §9's union law on a " +
	"different lattice: union of controls, intersection of permitted behavior, join of " +
	"classification levels. Three operations, one principle — the stricter reading wins, so " +
	"composing can never relax anything."

// OverClassification records how the source treats deliberate over-classification.
type OverClassification struct {
	Permitted             bool         `json:"permitted"`
	DocumentationRequired bool         `json:"documentation_required"`
	Citation              *CitationRef `json:"citation,omitempty"`
	Note                  string       `json:"note,omitempty"`
}

// Inherits records one profile layered over another from the same issuer.
type Inherits struct {
	ProfileID string `json:"profile_id"`
	// IssuerID must equal this profile's own issuer id — an overlay of another
	// institution's scheme is not an overlay, it is an assertion about somebody else's
	// policy.
	IssuerID string              `json:"issuer_id"`
	Relation InheritanceRelation `json:"relation"`
	Note     string              `json:"note,omitempty"`
	Citation *CitationRef        `json:"citation,omitempty"`
}

// InheritanceRelation is how one profile relates to the one it inherits from.
type InheritanceRelation string

// The inheritance relations.
const (
	// InheritsOverlays means this profile adds requirements on top of the named one
	// for a narrower scope, sharing its levels.
	InheritsOverlays InheritanceRelation = "overlays"
	// InheritsSharesLevels means the two use one classification table and neither is
	// on top.
	InheritsSharesLevels InheritanceRelation = "shares-levels-with"
)

// AllInheritanceRelations is the closed set.
var AllInheritanceRelations = []InheritanceRelation{InheritsOverlays, InheritsSharesLevels}

// UnmodeledAxis is an axis the source defines that this profile does not model.
//
// UC is why this type exists: IS-3 classifies on two independent axes, Protection
// (P1-P4) and Availability (A1-A4), and automat models the protection axis alone
// because that is what an account is rated for. A profile that simply omitted the
// availability axis would read to someone who knows IS-3 as an incomplete
// transcription, and to someone who does not as though UC had one axis.
type UnmodeledAxis struct {
	Name      string      `json:"name"`
	Statement string      `json:"statement"`
	Citation  CitationRef `json:"citation"`
}

// CitationRef is a pointer into a hashed source: which document, and which section of
// it.
//
// This is what "every control traces to a cited section" means mechanically — SourceID
// resolves against Profile.Sources and Section names the place a reader turns to. A
// claim with no CitationRef cannot be checked, and in a derived profile an unverifiable
// claim renders exactly as confidently as a verified one.
//
// A separate type from Citation, matching the schema's two $defs, because the two have
// different required fields and one Go struct for both would make required-ness a
// convention rather than a shape. A CitationRef always points INTO a document; a
// Citation names the document itself.
type CitationRef struct {
	SourceID string `json:"source_id"`
	// Section is where in the source, as the source labels it plus enough locator to
	// find it — "Section 3.1 Protection Levels (page 4)", "Minimum Security Standards:
	// Servers, Two-Step Authentication row".
	Section string `json:"section"`
	// Quote is the source's own words, where quoting them is what makes the claim
	// checkable at a glance. Optional: a quote for every control would be a
	// transcription of the source rather than a reading of it.
	Quote string `json:"quote,omitempty"`
}

// Citation is one published document this profile reads.
type Citation struct {
	// ID is the document's own identifier as published, where it has one — "SC-0002",
	// "IS-3 Part III Section 8". The institution's designation, not automat's.
	ID    string `json:"id"`
	Title string `json:"title"`
	// DateBasis says WHERE THE DATE COMES FROM, which institutional policy makes a
	// real question rather than a formality: a versioned standard carries an approval
	// date, while a living web page carries nothing at all. See DateRetrievedOnly.
	DateBasis DateBasis `json:"date_basis"`
	// EffectiveDate is required unless DateBasis is DateRetrievedOnly, and forbidden
	// when it is.
	EffectiveDate string `json:"effective_date,omitempty"`
	// SourceID is the Sources entry holding the retrieved bytes of this citation,
	// where it was retrieved.
	SourceID string   `json:"source_id,omitempty"`
	URI      string   `json:"uri,omitempty"`
	Role     CiteRole `json:"role,omitempty"`
	Note     string   `json:"note,omitempty"`
}

// DateBasis says where a citation's date comes from.
type DateBasis string

// The date bases.
const (
	DateEffective   DateBasis = "published-effective-date"
	DateLastUpdated DateBasis = "last-updated-in-document"
	// DateRetrievedOnly is for a living web page bearing no date at all, where the
	// retrieval timestamp in Sources is the only fact available. It exists so that a
	// dateless source is recorded as dateless: an effective date invented for a living
	// page would be automat's fabrication sitting in the field a reader checks for
	// staleness.
	DateRetrievedOnly DateBasis = "retrieved-only"
	// DateNotRetrieved is for a document automat has not read at all: named because a
	// reader needs to know it exists and governs, with retrieval attempted and failed,
	// or never attempted. Forbids both EffectiveDate and SourceID, unlike
	// DateRetrievedOnly, which forbids only the former — there are no retrieved bytes
	// for a SourceID to point at. Exists because the alternative was recording an
	// unread document as DateRetrievedOnly and pointing SourceID at a DIFFERENT
	// document the validator's old required-SourceID rule forced a name for (AUDIT-2
	// F5): the field a re-verifier reads asserted the wrong thing about which document
	// was read.
	DateNotRetrieved DateBasis = "not-retrieved"
)

// AllDateBases is the closed set.
var AllDateBases = []DateBasis{DateEffective, DateLastUpdated, DateRetrievedOnly, DateNotRetrieved}

// CiteRole says what a cited document does.
type CiteRole string

// The citation roles.
const (
	CiteDefinesLevels  CiteRole = "defines-levels"
	CiteStatesControls CiteRole = "states-controls"
	CiteGoverns        CiteRole = "governs"
	CiteRelated        CiteRole = "related"
)

// AllCiteRoles is the closed set.
var AllCiteRoles = []CiteRole{CiteDefinesLevels, CiteStatesControls, CiteGoverns, CiteRelated}

// HashedReference is a retrieved document, by hash.
//
// The same shape a control artifact uses for compile sources and an obligation profile
// uses for its instruments, for the same reason: a claim traceable to a hash can be
// re-verified, and one that is not cannot.
type HashedReference struct {
	// ID is what CitationRef.SourceID names. Patterned rather than free prose because
	// it is a key resolved within the document.
	ID    string `json:"id"`
	Title string `json:"title"`
	// Version is the document's own version or date designation, as published.
	// Distinct from RetrievedAt: a reading defended in a review is defended by version
	// rather than by when someone downloaded it.
	Version string `json:"version,omitempty"`
	// RetrievedAt is required here, unlike on the obligation profile's sources. For a
	// living policy web page the retrieval timestamp is frequently the ONLY dating
	// available, so it is the field a staleness check has to fall back on.
	RetrievedAt string `json:"retrieved_at"`
	URI         string `json:"uri,omitempty"`
	// MediaType is what was hashed. Recorded because re-verifying the hash of a web
	// page requires knowing that HTML bytes were hashed rather than extracted text,
	// and a hash nobody can reproduce the input for is decoration.
	MediaType string `json:"media_type,omitempty"`
	SHA256    string `json:"sha256"`
	Note      string `json:"note,omitempty"`
}

// Attestation is one provenance predicate over this document's content hash.
//
// A SIGNATURE ATTESTS PROVENANCE ONLY — never that the document is correct, that it
// applies to any institution, or that anyone approves its use. Role and Statement
// carry the claim; Signature is subordinate evidence for it. automat loads no trust
// policy, resolves no key, and performs no verification in v1 (DESIGN §11a).
//
// On a DERIVED profile only evidence.RoleInterpretedBy is admissible. The weaker roles
// are the danger, not the stronger ones: `reviewed-by` or `adopted-by` on automat's
// reading of an institution's policy is one inference away from "the institution
// reviewed this", which is the single claim a derived profile must never support.
//
// The role vocabulary is evidence.Role, shared rather than redeclared: the closed
// five-value set exists so the weakest claim cannot be read as the strongest, and two
// copies of a closed set is how one of them quietly gains a sixth value.
type Attestation struct {
	Role     evidence.Role `json:"role"`
	Identity string        `json:"identity"`
	// Statement is what makes this an attestation rather than a signature: the
	// identity says in its own words what it is claiming, so a reader evaluates a
	// sentence rather than a tick.
	Statement string `json:"statement"`
	// ContentSHA256 is the document hash this attestation is over.
	// VerifyAttestationSubjects recomputes it, because an attestation whose subject is
	// implicit is one that can be moved to another document.
	ContentSHA256 string     `json:"content_sha256"`
	AttestedAt    string     `json:"attested_at"`
	Signature     *Signature `json:"signature,omitempty"`
}

// Signature is the cryptographic material, when there is any.
type Signature struct {
	Format SignatureFormat `json:"format"`
	Value  string          `json:"value"`
	// KeyID names which key signed, for the detached form. Required there: a detached
	// signature nobody can locate a key for is unverifiable, which is worse than
	// absent because it looks verifiable.
	KeyID string `json:"key_id,omitempty"`
	// IdentityIssuer is the OIDC issuer that authenticated Identity, for the keyless
	// form. Required there and forbidden on the detached form, because in the keyless
	// model the issuer is the whole of what makes the identity mean anything.
	IdentityIssuer string `json:"identity_issuer,omitempty"`
}

// SignatureFormat names a signature encoding the schema admits.
//
// Declared here rather than reused from envprofile for the reason that package's own
// doc comment gives about not sharing a noun across document types — but the VALUES
// are deliberately the same two strings, and a test asserts the two sets agree. Two
// documents that admitted different signature formats would be two trust models.
type SignatureFormat string

// The signature formats. Neither is verified in v1.
const (
	FormatDetachedEd25519 SignatureFormat = "detached-ed25519"
	FormatOIDCBundle      SignatureFormat = "oidc-identity-bundle"
)

// AllSignatureFormats is the closed set.
var AllSignatureFormats = []SignatureFormat{FormatDetachedEd25519, FormatOIDCBundle}

// LevelByID returns the level with the given id, and whether it was found.
func (p *Profile) LevelByID(id string) (*Level, bool) {
	for i := range p.Levels {
		if p.Levels[i].ID == id {
			return &p.Levels[i], true
		}
	}
	return nil, false
}

// Highest returns the most protective level, or nil for a profile with none.
//
// By Rank, never by label or by position. Canonicalize sorts Levels by rank so the
// last element is the answer, but this reads the ranks anyway: a helper whose
// correctness depended on canonicalization having run is one that silently returns the
// wrong end of the scheme when it has not.
func (p *Profile) Highest() *Level {
	var out *Level
	for i := range p.Levels {
		if out == nil || p.Levels[i].Rank > out.Rank {
			out = &p.Levels[i]
		}
	}
	return out
}

// Join returns the higher of two levels of THIS profile: highest water mark.
//
// The composition operation the whole document type is shaped around, and DESIGN §9's
// union law on a different lattice — see CompositionRuleAssociates. Total order, so
// the join is a max over Rank, and the four laws `compile`'s property tests hold over
// control sets hold here too: idempotent (join(a,a) = a), commutative, associative,
// and monotone (raising either input cannot lower the result).
//
// Both levels must belong to this profile. Joining across institutions is refused
// rather than answered: UC's P3 and Stanford's Moderate are not comparable, and a tool
// that returned one of them would be asserting an equivalence neither institution
// published. That is a genuine gap — a cross-institution mapping is a real thing an
// operator might want — and it is left to a person for the same reason a
// classification is.
func (p *Profile) Join(a, b string) (*Level, error) {
	la, ok := p.LevelByID(a)
	if !ok {
		return nil, &UnknownLevelError{ProfileID: p.Meta.ID, LevelID: a, Known: p.LevelIDs()}
	}
	lb, ok := p.LevelByID(b)
	if !ok {
		return nil, &UnknownLevelError{ProfileID: p.Meta.ID, LevelID: b, Known: p.LevelIDs()}
	}
	if lb.Rank > la.Rank {
		return lb, nil
	}
	return la, nil
}

// LevelIDs returns the level ids in rank order, least protective first.
func (p *Profile) LevelIDs() []string {
	out := make([]string, 0, len(p.Levels))
	for _, l := range byRank(p.Levels) {
		out = append(out, l.ID)
	}
	return out
}
