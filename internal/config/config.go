// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package config loads automat's on-disk configuration.
//
// Its role in the vend pipeline is to answer the questions preflight and vend
// cannot discover from AWS: which OU to vend into, which vendor role to assume,
// where the ExternalId lives, and what email pattern to use. Everything else is
// read from the organization at run time, because configuration that duplicates
// discoverable state goes stale and then lies.
//
// Plain TOML, no viper (CLAUDE.md project facts). Two consequences worth stating:
// unknown keys are refused, so a misspelled setting fails loudly rather than
// silently reverting to a default; and there is no environment-variable overlay,
// so what the file says is what the run used — which matters when a config value
// ends up quoted in an evidence manifest.
//
// # Secrets
//
// This file never holds a credential (DESIGN §13). The ExternalId is referenced
// by *source*, not stored: see ExternalIDRef. An ExternalId is not quite a
// secret — it defends against the confused-deputy problem, not against an
// attacker who already reads your disk — but writing it into a file that
// operators share, commit, and paste into tickets is how it stops doing even
// that job.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the parsed configuration file.
type Config struct {
	// Contexts are named org contexts. A run selects one by name; with exactly
	// one defined, it is the default.
	Contexts map[string]Context `toml:"context"`
	// DefaultContext names the context to use when none is given.
	DefaultContext string `toml:"default_context"`
}

// Context is everything automat needs to know about one organization that it
// cannot learn by asking AWS.
type Context struct {
	// Org is the organization id, recorded so a config accidentally pointed at
	// the wrong org fails fast instead of vending into it. Optional; when set,
	// preflight checks it.
	Org string `toml:"org"`
	// OU is the target OU id that vending places accounts into, and the subtree
	// the delegation policy is scoped to.
	OU string `toml:"ou"`
	// VendorRoleARN is the role in the management account that automat assumes
	// for create/move/OU operations in MEMBER state (DESIGN §5).
	VendorRoleARN string `toml:"vendor_role_arn"`
	// ExternalIDRef names where the ExternalId comes from, not what it is. See
	// ExternalIDRef for the accepted forms.
	ExternalIDRef string `toml:"external_id_ref"`
	// EmailPattern generates account emails, e.g.
	// "research-admin+{name}@dept.edu". The {name} placeholder is required when
	// the pattern is set.
	EmailPattern string `toml:"email_pattern"`
	// Region is the region API calls are made in. Organizations is global but
	// the SDK still requires one.
	Region string `toml:"region"`
	// Profile is the AWS shared-config profile to resolve credentials from.
	Profile string `toml:"profile"`

	// SSOStartURL is the identity provider's start URL for `automat login`,
	// e.g. "https://example.awsapps.com/start". Optional: an operator who gets
	// credentials from a profile, an instance role, or a federated session never
	// needs it, because every other command reads the standard credential chain.
	SSOStartURL string `toml:"sso_start_url"`
	// SSORegion is the region the identity store lives in, which is not
	// necessarily Region — an organization vending into us-west-2 may well have
	// its SSO instance in us-east-1. Kept separate rather than reusing Region so
	// that getting one wrong cannot silently mean the other.
	SSORegion string `toml:"sso_region"`
}

// DefaultPath returns the config file path, honoring XDG_CONFIG_HOME.
func DefaultPath() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "automat", "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory for the config file: %w", err)
	}
	return filepath.Join(home, ".config", "automat", "config.toml"), nil
}

// Load reads and validates the config file at path.
//
// A missing file is not an error: automat runs without configuration in
// STANDALONE and MANAGEMENT states, where everything it needs is discoverable.
// The returned bool reports whether a file was found, so a caller can tell
// "no config" from "empty config" when explaining a missing setting.
func Load(path string) (*Config, bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator's own config path
	if errors.Is(err, os.ErrNotExist) {
		return &Config{Contexts: map[string]Context{}}, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := Decode(data, path)
	if err != nil {
		return nil, true, err
	}
	return cfg, true, nil
}

// Decode parses config bytes. path is used in error messages only.
func Decode(data []byte, path string) (*Config, error) {
	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// A misspelled key would otherwise be dropped in silence and the setting
	// would revert to a default — the same class of defect as AUDIT-0 H2, where
	// "parmeters" silently deleted a control's parameters. A config typo that
	// reverts vendor_role_arn to empty turns a brokered vend into a confusing
	// permission error.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("parse config %s: unrecognized %s: %s — "+
			"a misspelled key would silently revert the setting to its default, so it is refused; "+
			"remove it or correct the spelling",
			path, plural("key", len(keys)), strings.Join(keys, ", "))
	}
	if err := checkKeyCase(md.Keys(), path); err != nil {
		return nil, err
	}
	if cfg.Contexts == nil {
		cfg.Contexts = map[string]Context{}
	}
	if err := cfg.validate(path); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// The exact spellings of every key. Kept as literals rather than derived by
// reflection so that a struct-tag change has to be made in two places
// deliberately, and TestEveryFieldIsCaseChecked catches a field added to one and
// not the other.
var (
	configTags  = map[string]bool{"context": true, "default_context": true}
	contextTags = map[string]bool{
		"org": true, "ou": true, "vendor_role_arn": true, "external_id_ref": true,
		"email_pattern": true, "region": true, "profile": true,
		"sso_start_url": true, "sso_region": true,
	}
)

// checkKeyCase refuses a key whose spelling differs from the documented one only
// by case.
//
// BurntSushi/toml matches keys to struct fields case-insensitively, so `OU` and
// `ou` are two distinct TOML keys that decode into the same field: the later one
// wins and MetaData.Undecoded() reports nothing. That is a document that reads
// one way and loads another, in the file that names the OU a delegation policy is
// scoped to — the AUDIT-0 H2 defect class again, and the same reason it is
// refused rather than warned about.
func checkKeyCase(keys []toml.Key, path string) error {
	for _, k := range keys {
		var want map[string]bool
		switch len(k) {
		case 1:
			want = configTags
		case 3:
			// [context.<name>].<field> — element 1 is an operator-chosen name.
			want = contextTags
		default:
			continue
		}
		leaf := k[len(k)-1]
		if want[leaf] {
			continue
		}
		// Undecoded() already rejected genuinely unknown keys, so anything left
		// that is not an exact match differs only by case.
		for tag := range want {
			if strings.EqualFold(tag, leaf) {
				return fmt.Errorf("parse config %s: key %q is spelled %q — automat's keys are lowercase, "+
					"and TOML treats the two spellings as different keys that decode into the same "+
					"setting, so a file containing both would load a value it does not appear to say; "+
					"use %q",
					path, k.String(), leaf, tag)
			}
		}
	}
	return nil
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

var (
	reOrgID   = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	reOUID    = regexp.MustCompile(`^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$`)
	reRoleARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$`)
	// A region name, deliberately strict: this value reaches an SDK endpoint
	// resolver, and a region containing a dot or a slash is a value that has been
	// mistaken for a hostname or a path somewhere upstream.
	reRegion = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d$`)
)

// validateSSOStartURL checks the start URL without resolving it. Kept here rather
// than only in internal/login so that `automat preflight` on a bad config reports
// the problem before any credential exchange is attempted.
func validateSSOStartURL(raw string) error {
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("%q has surrounding whitespace, which makes it read as valid and "+
			"compare as something else", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%q uses scheme %q; automat requires https, because the login flow "+
			"exchanges a bearer token over it", raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host; it should look like https://example.awsapps.com/start", raw)
	}
	return nil
}

// validate checks the shape of every value that will later be interpolated into
// an ARN, a policy document, or an API call.
//
// This is a security boundary, not tidiness. An OU id reaches a delegation
// policy's Resource ARN and a MoveAccount destination; an unvalidated value
// there could widen the policy's scope past the subtree the operator meant to
// name. The same argument applies to the role ARN, which lands in a trust policy
// central IT reviews and approves.
func (c *Config) validate(path string) error {
	if c.DefaultContext != "" {
		if _, ok := c.Contexts[c.DefaultContext]; !ok {
			return fmt.Errorf("config %s: default_context names %q, which is not defined — "+
				"define [context.%s] or correct the name", path, c.DefaultContext, c.DefaultContext)
		}
	}
	for name, ctx := range c.Contexts {
		where := fmt.Sprintf("config %s: context %q", path, name)
		if ctx.Org != "" && !reOrgID.MatchString(ctx.Org) {
			return fmt.Errorf("%s: org %q is not an organization id — "+
				"use the o-... form from `automat preflight`", where, ctx.Org)
		}
		if ctx.OU != "" && !reOUID.MatchString(ctx.OU) {
			return fmt.Errorf("%s: ou %q is not an OU id — use the ou-<root>-<suffix> form; "+
				"this value is interpolated into policy resource ARNs, so it is not accepted loosely",
				where, ctx.OU)
		}
		if ctx.VendorRoleARN != "" && !reRoleARN.MatchString(ctx.VendorRoleARN) {
			return fmt.Errorf("%s: vendor_role_arn %q is not an IAM role ARN — "+
				"use arn:aws:iam::<management-account-id>:role/<role-name>", where, ctx.VendorRoleARN)
		}
		if ctx.EmailPattern != "" && !strings.Contains(ctx.EmailPattern, "{name}") {
			return fmt.Errorf("%s: email_pattern %q has no {name} placeholder, so every account would "+
				"request the same address and all but the first would fail — "+
				"AWS requires a globally unique email per account", where, ctx.EmailPattern)
		}
		if ctx.ExternalIDRef != "" {
			if err := validateExternalIDRef(ctx.ExternalIDRef); err != nil {
				return fmt.Errorf("%s: external_id_ref: %w", where, err)
			}
		}
		// The start URL decides where a bearer token is exchanged and where it
		// is cached. Refused here rather than only at login time, so a config
		// file with an http:// start URL is a validation error the operator sees
		// before it becomes a downgraded credential exchange.
		if ctx.SSOStartURL != "" {
			if err := validateSSOStartURL(ctx.SSOStartURL); err != nil {
				return fmt.Errorf("%s: sso_start_url: %w", where, err)
			}
		}
		if ctx.SSORegion != "" && !reRegion.MatchString(ctx.SSORegion) {
			return fmt.Errorf("%s: sso_region %q is not a region name — use the us-east-1 form",
				where, ctx.SSORegion)
		}
		if ctx.Region != "" && !reRegion.MatchString(ctx.Region) {
			return fmt.Errorf("%s: region %q is not a region name — use the us-east-1 form",
				where, ctx.Region)
		}
	}
	return nil
}

// Context returns the named context, or the default when name is empty.
func (c *Config) Context(name string) (Context, error) {
	if name != "" {
		ctx, ok := c.Contexts[name]
		if !ok {
			return Context{}, fmt.Errorf("no context named %q is defined; %s",
				name, c.describeContexts())
		}
		return ctx, nil
	}
	if c.DefaultContext != "" {
		return c.Contexts[c.DefaultContext], nil
	}
	if len(c.Contexts) == 1 {
		for _, ctx := range c.Contexts {
			return ctx, nil
		}
	}
	if len(c.Contexts) == 0 {
		return Context{}, nil
	}
	return Context{}, fmt.Errorf("several contexts are defined and none is the default; %s, "+
		"or set default_context", c.describeContexts())
}

func (c *Config) describeContexts() string {
	if len(c.Contexts) == 0 {
		return "the config file defines none"
	}
	names := make([]string, 0, len(c.Contexts))
	for name := range c.Contexts {
		names = append(names, name)
	}
	// Sorted so the message is stable across runs; a map iteration order that
	// shuffled the suggestion would make the error look nondeterministic.
	sortStrings(names)
	return "select one with --context: " + strings.Join(names, ", ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
