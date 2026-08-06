// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

import "github.com/scttfrdmn/automat/internal/evidence"

// SchemaVersion is the environment-profile schema version this build emits.
const SchemaVersion = "1.0.0"

// Profile is one environment profile: `vend`'s input document (DESIGN §7).
//
// Named Profile inside a package named envprofile rather than EnvironmentProfile,
// so callers read `envprofile.Profile` — which says which of the three document
// types it is at the use site, where the ambiguity Q14 removed actually bit.
//
// Field order follows the schema's for MarshalIndented's readability only; the
// content hash goes through canonical form, which sorts keys.
type Profile struct {
	SchemaVersion string `json:"schema_version"`
	Meta          Meta   `json:"environment_profile"`
	// ReviewBy is the date by which this document must be re-read against the
	// posture it deploys. Required, with no default: left alone, an environment
	// profile keeps vending a posture someone approved once, and every account it
	// produces looks as current as the day it was written.
	//
	// Inside the content hash, so extending it is a change no earlier attestation
	// vouches for. `verify` warns once it has passed — warns rather than fails,
	// because what has lapsed is anyone's assurance that the document still reads
	// policy correctly, not the account's posture (DESIGN §11a).
	ReviewBy string `json:"review_by"`
	// Signatures are optional attestations over this document's content hash.
	// PROVENANCE ONLY, and automat verifies none of them in v1: see Attestation.
	Signatures []Attestation `json:"signatures,omitempty"`
	// ControlSets are the control set ids to compile for this vend, by union.
	ControlSets []string `json:"control_sets"`
	// Permitted is the permitted-behavior boundary. Nil means the profile adds no
	// boundary of its own, which is not the same as permitting everything: the
	// compiled control sets' own allowlists still apply. See Permitted.
	Permitted *Permitted `json:"permitted,omitempty"`
	// Obligations are the obligation profiles this environment is built to
	// satisfy, RECORDED rather than resolved — automat does not decide that an
	// obligation applies.
	Obligations []ObligationRef `json:"obligations,omitempty"`
	Placement   Placement       `json:"placement"`
	Account     *Account        `json:"account,omitempty"`
	Baseline    Baseline        `json:"baseline"`
}

// Meta is the profile's identity.
type Meta struct {
	// ID is a round-trip field (CLAUDE.md rule 8): it is written into account
	// tags, SCP names, and evidence records, and an operator reads it back and
	// types it. Patterned at both layers.
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// Permitted is the permitted-behavior boundary: which regions and which service
// namespaces principals in the vended account may call.
//
// # These only ever narrow
//
// Each set is INTERSECTED with the corresponding allowlist the compiled control
// sets require — never substituted for it, never added to it. Union of controls,
// intersection of permitted behavior (DESIGN §9). An institution therefore cannot
// widen its own posture by editing an environment profile, which is the whole
// reason these fields are safe to expose in an operator-editable document rather
// than only in a reviewed catalog.
//
// The intersection itself is not performed here. It lives in
// compilesets.Narrow, with the packer that renders the resulting Deny and the
// property tests that hold the narrowing invariant over everything it can emit;
// a second implementation in this package would be a second answer to "did this
// widen".
//
// # Distinct from Baseline.Regions
//
// That field is opt-in region ENABLEMENT via the Account Management API. One is a
// boundary (what a principal may call), the other an account-level action taken
// once at baseline time. Neither implies the other and they are separate fields on
// purpose: an operator can legitimately enable a region without permitting calls
// in it, or permit one in policy that was never enabled (E2).
type Permitted struct {
	// Regions is the permitted-region allowlist. Nil means this profile constrains
	// no regions; a non-nil empty slice is refused by Validate, because an empty
	// allowlist is not a strict policy but a deny-all — see MinPermittedMembers.
	Regions []string `json:"regions,omitempty"`
	// Services is the permitted-service-namespace allowlist, same treatment.
	//
	// The globally addressed services do not belong here and must not be relied on
	// being absent: they are spared by the control artifact's own
	// region_deny_exempt_services, which is catalog data rather than a compiled-in
	// list precisely because getting it wrong bricks an account.
	Services []string `json:"services,omitempty"`
}

// MinPermittedMembers is the floor on a non-nil permitted set: one member.
//
// Not a style rule. An empty allowlist denies every call in the account — including
// the ones automat's own baseline makes — and it would be discovered after create
// and move had already succeeded, because the empty set is the absorbing element of
// the meet (AUDIT-0's H5). The schema states it as minItems, Validate states it
// here, and an intersection that evaluates to empty is a separate hard error at
// plan time naming which inputs produced the emptiness.
const MinPermittedMembers = 1

// ObligationRef names one obligation profile this environment is built to satisfy,
// plus any determination that profile left to the operator.
type ObligationRef struct {
	// ID is the obligation profile id — `cmmc-l1`, `dfars-7012`, `nih-cadr-dua`.
	ID string `json:"id"`
	// ContentSHA256 is the referenced profile's content hash, required for the
	// reason an evidence record's is: an obligation profile is a reading of policy
	// that moves — notices are superseded, phase-in dates arrive, a class deviation
	// pinning a revision expires — so a reference naming only an id has a subject
	// that can be rewritten under it.
	ContentSHA256 string `json:"content_sha256"`
	// RevisionDetermination is required exactly when the referenced obligation
	// profile declares `revision_policy: operator-determined`, and forbidden
	// otherwise.
	//
	// Neither the schema nor Validate can enforce that pairing, because it depends
	// on the OTHER document: CheckObligations does, given the profiles. The failure
	// is a hard error rather than a default — automat ships no default revision,
	// since a tool that silently picks one has made a compliance determination on
	// the institution's behalf, and the person best placed to make it is exactly
	// the person a default routes around.
	RevisionDetermination *Determination `json:"revision_determination,omitempty"`
}

// Determination is a decision automat is not entitled to make, recorded with who
// made it and when.
//
// Every field is required. A determination with no named determiner is an anonymous
// claim in a document an institution acts on; one with no date cannot be checked for
// staleness against ReviewBy; and Statement is required for the reason
// Attestation.Statement is — a bare value invites the reader to supply the
// justification, and they supply the strongest one available.
//
// Hashed with the rest of the document, so a determination cannot be rewritten
// under material that still verifies.
type Determination struct {
	Value        string `json:"value"`
	DeterminedBy string `json:"determined_by"`
	DeterminedAt string `json:"determined_at"`
	Statement    string `json:"statement"`
}

// Attestation is one provenance predicate over this document's content hash.
//
// A SIGNATURE ATTESTS PROVENANCE ONLY — never that the document is correct, that it
// applies to any institution, or that anyone approves its use. Role and Statement
// carry the claim; Signature is subordinate evidence for it, and an entry with no
// Signature is still a recordable attestation. automat loads no trust policy,
// resolves no key, and performs no verification in v1 (DESIGN §11a).
//
// The role vocabulary is evidence.Role, shared rather than redeclared: the closed
// five-value set exists so the weakest claim cannot be read as the strongest, and
// two copies of a closed set is how one of them quietly gains a sixth value.
type Attestation struct {
	Role     evidence.Role `json:"role"`
	Identity string        `json:"identity"`
	// Statement is what makes this an attestation rather than a signature: the
	// identity says in its own words what it is claiming, so a reader evaluates a
	// sentence rather than a tick.
	Statement string `json:"statement"`
	// ContentSHA256 is the document hash this attestation is over. Recorded inside
	// the document, which no schema can check for self-consistency —
	// VerifyAttestationSubjects recomputes it. Present anyway, because an
	// attestation whose subject is implicit is one that can be moved to another
	// document.
	ContentSHA256 string     `json:"content_sha256"`
	AttestedAt    string     `json:"attested_at"`
	Signature     *Signature `json:"signature,omitempty"`
}

// Signature is the cryptographic material, when there is any.
type Signature struct {
	Format SignatureFormat `json:"format"`
	Value  string          `json:"value"`
	// KeyID names which key signed, for the detached form. Required there: a
	// detached signature nobody can locate a key for is unverifiable, which is
	// worse than absent because it looks verifiable.
	KeyID string `json:"key_id,omitempty"`
	// IdentityIssuer is the OIDC issuer that authenticated Identity, for the
	// keyless form. Required there and forbidden on the detached form, because in
	// the keyless model the issuer is the whole of what makes the identity mean
	// anything: "signed by security@example.edu" is a different claim depending on
	// who vouched for that address.
	IdentityIssuer string `json:"identity_issuer,omitempty"`
}

// SignatureFormat names a signature encoding the schema admits.
type SignatureFormat string

// The signature formats. Neither is verified in v1; both are named now so that
// adopting the second is not a schema version event (DESIGN §11a).
const (
	// FormatDetachedEd25519 is a raw detached signature over the content hash,
	// verified against a public key the operator obtains out of band.
	FormatDetachedEd25519 SignatureFormat = "detached-ed25519"
	// FormatOIDCBundle is the intended v2 mechanism: a keyless signature bound to
	// an OIDC identity, so an institution never has to run a key ceremony.
	FormatOIDCBundle SignatureFormat = "oidc-identity-bundle"
)

// AllSignatureFormats is the closed set.
var AllSignatureFormats = []SignatureFormat{FormatDetachedEd25519, FormatOIDCBundle}

// Placement is where the vended account lands.
//
// New accounts always materialize under the root and are then moved (DESIGN §3,
// fact 4), so this describes the destination of a move rather than a creation
// parameter.
type Placement struct {
	TargetOU string `json:"target_ou"`
	// CreateIntermediateOUs permits creating missing OUs on the path, bounded by
	// the five-level nesting limit (DESIGN §3, fact 10).
	CreateIntermediateOUs bool `json:"create_intermediate_ous,omitempty"`
	// OUPath names OUs to ensure beneath TargetOU, outermost first.
	OUPath []string `json:"ou_path,omitempty"`
}

// MaxOUPathDepth is the OU nesting limit under a root (DESIGN §3, fact 10).
const MaxOUPathDepth = 5

// Account holds account-creation settings.
type Account struct {
	// EmailPattern is a template in which EmailNamePlaceholder is substituted with
	// the account name. Each account needs a globally unique email (DESIGN §3,
	// fact 11).
	EmailPattern string `json:"email_pattern,omitempty"`
	// RoleName is the management-assumable role created in the child. Empty means
	// DefaultOrgAccessRole (DESIGN §3, fact 6).
	RoleName string `json:"role_name,omitempty"`
	// IAMUserAccessToBilling is passed through to CreateAccount. Empty means
	// BillingAccessAllow, matching the API's own default.
	IAMUserAccessToBilling BillingAccess `json:"iam_user_access_to_billing,omitempty"`
	// Tags are additional tags applied at creation. automat's conventional tags
	// (DESIGN §14) are always applied and may not be overridden here — the
	// `automat:` prefix is refused, because baseline-protection SCPs read those
	// keys in conditions and a key an operator can write at the same scope is one
	// that can be forged (AUDIT-1's C1).
	Tags map[string]string `json:"tags,omitempty"`
}

// EmailNamePlaceholder is what EmailPattern substitutes the account name for.
const EmailNamePlaceholder = "{name}"

// DefaultOrgAccessRole is the role CreateAccount makes in the child when the
// profile names none (DESIGN §3, fact 6).
const DefaultOrgAccessRole = "OrganizationAccountAccessRole"

// BillingAccess is CreateAccount's IamUserAccessToBilling parameter.
type BillingAccess string

// The billing-access values.
const (
	BillingAccessAllow BillingAccess = "ALLOW"
	BillingAccessDeny  BillingAccess = "DENY"
)

// AllBillingAccess is the closed set.
var AllBillingAccess = []BillingAccess{BillingAccessAllow, BillingAccessDeny}

// Baseline is the in-child work performed after assuming into the account
// (DESIGN §7, step 5).
type Baseline struct {
	ConfigRecorder ConfigRecorder `json:"config_recorder"`
	// Regions is opt-in region ENABLEMENT, not the permitted-region boundary. See
	// Permitted for why the two are separate fields.
	Regions        *BaselineRegions `json:"regions,omitempty"`
	AutomationRole *AutomationRole  `json:"automation_role,omitempty"`
	// DisableOrgAccessRoleAfterVend restricts further use of the
	// management-assumable role once baselining completes.
	DisableOrgAccessRoleAfterVend bool           `json:"disable_org_access_role_after_vend,omitempty"`
	Attestations                  *OutputTargets `json:"attestations,omitempty"`
	Evidence                      *OutputTargets `json:"evidence,omitempty"`
}

// ConfigRecorder is the detective baseline's recorder settings.
type ConfigRecorder struct {
	Enabled bool `json:"enabled"`
	// AllSupportedResources and IncludeGlobalResourceTypes are pointers because
	// their schema default is true, and a plain bool cannot distinguish "the
	// profile said false" from "the profile said nothing". Defaulting a recording
	// scope to the narrower reading of an absent field would silently reduce what
	// is recorded.
	AllSupportedResources      *bool  `json:"all_supported_resources,omitempty"`
	IncludeGlobalResourceTypes *bool  `json:"include_global_resource_types,omitempty"`
	DeliveryBucket             string `json:"delivery_bucket,omitempty"`
}

// RecordsAllSupportedResources reports the effective value, applying the schema
// default for an absent field.
func (c ConfigRecorder) RecordsAllSupportedResources() bool {
	return c.AllSupportedResources == nil || *c.AllSupportedResources
}

// RecordsGlobalResourceTypes reports the effective value, applying the schema
// default for an absent field.
func (c ConfigRecorder) RecordsGlobalResourceTypes() bool {
	return c.IncludeGlobalResourceTypes == nil || *c.IncludeGlobalResourceTypes
}

// BaselineRegions is opt-in region enablement, performed in-child via the Account
// Management API.
type BaselineRegions struct {
	Home    string   `json:"home,omitempty"`
	Enable  []string `json:"enable,omitempty"`
	Disable []string `json:"disable,omitempty"`
}

// AutomationRole is the least-privilege in-account role automat uses for future
// `verify` runs, and which baseline-protection SCPs exempt (DESIGN §10).
type AutomationRole struct {
	// Name is empty for DefaultAutomationRoleName.
	Name string `json:"name,omitempty"`
	// Create is a pointer because its schema default is true: a plain bool would
	// make an absent field mean "do not create the role", and the SCP exemptions
	// that name it would then point at a principal that does not exist.
	Create *bool `json:"create,omitempty"`
}

// DefaultAutomationRoleName is the in-account automation role's name when the
// profile names none.
const DefaultAutomationRoleName = "automat-automation"

// RoleName returns the effective role name.
func (a *AutomationRole) RoleName() string {
	if a == nil || a.Name == "" {
		return DefaultAutomationRoleName
	}
	return a.Name
}

// ShouldCreate reports the effective value, applying the schema default.
func (a *AutomationRole) ShouldCreate() bool {
	if a == nil {
		return true
	}
	return a.Create == nil || *a.Create
}

// OutputTargets says where a class of vend output is written: always a local
// directory, optionally also S3.
//
// One type for attestation stubs and evidence manifests because the schema gives
// them the same three fields, minus the management mirror — see
// ManagementMirrorBucket.
type OutputTargets struct {
	// LocalDir is relative to the working directory and must stay contained. A
	// local copy is always written (DESIGN §11), so an empty value means the
	// caller's default rather than "write nothing".
	LocalDir        string `json:"local_dir,omitempty"`
	InAccountBucket string `json:"in_account_bucket,omitempty"`
	// ManagementMirrorBucket is meaningful for evidence only, where DESIGN §11
	// allows a copy in the management account. Set on an attestations block it is
	// refused by Validate rather than ignored: a field that is silently dropped
	// reads to an operator as a mirror that exists.
	ManagementMirrorBucket string `json:"management_mirror_bucket,omitempty"`
}

// Dir returns the effective local directory, falling back to def.
func (o *OutputTargets) Dir(def string) string {
	if o == nil || o.LocalDir == "" {
		return def
	}
	return o.LocalDir
}

// DefaultAttestationDir and DefaultEvidenceDir mirror the schema's defaults.
const (
	DefaultAttestationDir = "compliance"
	DefaultEvidenceDir    = "evidence"
)

// Ref returns the reference an evidence record carries for this profile: id,
// content hash, schema version, review-by date, and an EMPTY verified-signature
// set.
//
// Empty and non-nil, always, and that is the point rather than an omission.
// automat verifies nothing in v1, so it records the empty set as an answer; the
// difference between "nothing verified" and "the question was never asked" is
// exactly the one an evidence record must not blur. Copying this document's own
// Signatures into it would be manufacturing assurance out of a document's claims
// about itself (DESIGN §11a).
//
// The hash is passed in rather than recomputed so the caller controls which bytes
// the record attests to — normally ContentHash's result on the document as loaded.
func (p *Profile) Ref(contentHash string) *evidence.EnvProfileRef {
	return &evidence.EnvProfileRef{
		ID:                 p.Meta.ID,
		ContentSHA256:      contentHash,
		SchemaVersion:      p.SchemaVersion,
		ReviewBy:           p.ReviewBy,
		VerifiedSignatures: []evidence.VerifiedSignature{},
	}
}
