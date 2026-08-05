// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const goodConfig = `
default_context = "research"

[context.research]
org = "o-exampleorgid"
ou = "ou-exam-research1"
vendor_role_arn = "arn:aws:iam::111111111111:role/automat-vendor"
external_id_ref = "env:AUTOMAT_EXTERNAL_ID"
email_pattern = "aws-research+{name}@example.edu"
region = "us-east-1"
profile = "research-admin"
`

func TestDecodeAcceptsAWellFormedConfig(t *testing.T) {
	cfg, err := Decode([]byte(goodConfig), "test.toml")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ctx, err := cfg.Context("")
	if err != nil {
		t.Fatalf("Context: %v", err)
	}
	if ctx.OU != "ou-exam-research1" || ctx.Profile != "research-admin" {
		t.Errorf("context did not round-trip: %+v", ctx)
	}
}

// TestDecodeRejectsUnknownKeys is AUDIT-0 H2's defect class in a second place: a
// misspelled key that is silently dropped reverts a setting to its default, and
// the setting in question decides whether a vend is brokered.
func TestDecodeRejectsUnknownKeys(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want string
	}{
		{"misspelled context key", `
[context.research]
vendor_role_ann = "arn:aws:iam::111111111111:role/automat-vendor"
`, "vendor_role_ann"},
		{"misspelled top-level key", `default_contxt = "research"`, "default_contxt"},
		{"stray key", `
[context.research]
ou = "ou-exam-research1"
notes = "for the audit"
`, "notes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.toml), "test.toml")
			if err == nil {
				t.Fatal("a misspelled key was accepted and its value silently dropped")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should name the offending key %q: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "silently revert") {
				t.Errorf("error should explain why this is refused rather than warned about: %v", err)
			}
		})
	}
}

// TestDecodeRejectsCaseVariantKeys.
//
// BurntSushi/toml matches keys to struct fields case-insensitively, so `OU` and
// `ou` are two *different* TOML keys that decode into the same field. The later
// one wins and Undecoded() reports nothing, which means a config file can read one
// way and load another — in the file that names the OU a delegation policy is
// scoped to. Undecoded() cannot catch this because both keys are "known".
func TestDecodeRejectsCaseVariantKeys(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{"both spellings of ou", `
[context.a]
ou = "ou-exam-research1"
OU = "ou-exam-research2"
`},
		{"only the wrong spelling", `
[context.a]
OU = "ou-exam-research2"
`},
		{"mixed-case role arn key", `
[context.a]
Vendor_Role_Arn = "arn:aws:iam::111111111111:role/automat-vendor"
`},
		{"mixed-case top-level key", `
Default_Context = "a"

[context.a]
ou = "ou-exam-research1"
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Decode([]byte(tc.toml), "test.toml")
			if err == nil {
				t.Fatalf("accepted a case-variant key; the config loaded as %+v, which is not what it says",
					cfg.Contexts["a"])
			}
			if !strings.Contains(err.Error(), "lowercase") {
				t.Errorf("error should say which spelling is correct: %v", err)
			}
		})
	}
}

// TestEveryFieldIsCaseChecked keeps the case check honest as the config grows: a
// field added to Config or Context without a matching entry in the tag maps would
// silently stop being protected.
func TestEveryFieldIsCaseChecked(t *testing.T) {
	for _, tc := range []struct {
		what  string
		typ   reflect.Type
		known map[string]bool
	}{
		{"Config", reflect.TypeOf(Config{}), configTags},
		{"Context", reflect.TypeOf(Context{}), contextTags},
	} {
		t.Run(tc.what, func(t *testing.T) {
			for i := range tc.typ.NumField() {
				tag := tc.typ.Field(i).Tag.Get("toml")
				if tag == "" || tag == "-" {
					continue
				}
				if !tc.known[tag] {
					t.Errorf("%s.%s has toml tag %q, which is missing from the case-check map — "+
						"a case-variant spelling of it would silently override the documented one",
						tc.what, tc.typ.Field(i).Name, tag)
				}
			}
			if got, want := len(tc.known), countTaggedFields(tc.typ); got != want {
				t.Errorf("the case-check map has %d entries for %d tagged fields; a stale entry means "+
					"a key that no longer exists is being guarded", got, want)
			}
		})
	}
}

func countTaggedFields(t reflect.Type) int {
	var n int
	for i := range t.NumField() {
		if tag := t.Field(i).Tag.Get("toml"); tag != "" && tag != "-" {
			n++
		}
	}
	return n
}

// TestValidateRejectsMalformedIdentifiers. These values are interpolated into
// policy resource ARNs and API parameters, so a loose validator here is a policy
// scope the operator did not write.
func TestValidateRejectsMalformedIdentifiers(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want string
	}{
		{"org id not an org id", `
[context.a]
org = "111111111111"
`, "organization id"},
		{"OU id missing the suffix", `
[context.a]
ou = "ou-exam"
`, "OU id"},
		{"OU id is a root id", `
[context.a]
ou = "r-exam"
`, "OU id"},
		{"OU id with a wildcard", `
[context.a]
ou = "ou-exam-*"
`, "OU id"},
		{"OU id with a policy ARN smuggled in", `
[context.a]
ou = "ou-exam-research1/*"
`, "OU id"},
		{"role ARN is a user ARN", `
[context.a]
vendor_role_arn = "arn:aws:iam::111111111111:user/operator"
`, "IAM role ARN"},
		{"role ARN with a short account id", `
[context.a]
vendor_role_arn = "arn:aws:iam::1111:role/automat-vendor"
`, "IAM role ARN"},
		{"role ARN with an embedded newline", `
[context.a]
vendor_role_arn = "arn:aws:iam::111111111111:role/vendor\nrole"
`, "IAM role ARN"},
		{"email pattern with no placeholder", `
[context.a]
email_pattern = "aws-research@example.edu"
`, "{name}"},
		{"default_context names nothing", `
default_context = "nope"

[context.a]
ou = "ou-exam-research1"
`, "not defined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.toml), "test.toml")
			if err == nil {
				t.Fatal("accepted a value that reaches a policy resource ARN unvalidated")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q: %v", tc.want, err)
			}
		})
	}
}

func TestValidateAcceptsLegitimateVariants(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{"empty config", ``},
		{"partial context", `
[context.a]
ou = "ou-exam-research1"
`},
		{"govcloud role ARN", `
[context.a]
vendor_role_arn = "arn:aws-us-gov:iam::111111111111:role/automat-vendor"
`},
		{"role with a path", `
[context.a]
vendor_role_arn = "arn:aws:iam::111111111111:role/automat/vendor"
`},
		{"file external id ref", `
[context.a]
external_id_ref = "file:~/.config/automat/external-id"
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode([]byte(tc.toml), "test.toml"); err != nil {
				t.Errorf("rejected a valid config: %v", err)
			}
		})
	}
}

func TestContextSelection(t *testing.T) {
	const two = `
[context.a]
ou = "ou-exam-research1"

[context.b]
ou = "ou-exam-research2"
`
	cfg, err := Decode([]byte(two), "test.toml")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	t.Run("named", func(t *testing.T) {
		ctx, err := cfg.Context("b")
		if err != nil || ctx.OU != "ou-exam-research2" {
			t.Errorf("Context(b) = %+v, %v", ctx, err)
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		_, err := cfg.Context("")
		if err == nil {
			t.Fatal("two contexts and no default must not silently pick one")
		}
		// The suggestion is sorted so the message does not look nondeterministic
		// across runs of the same broken config.
		if !strings.Contains(err.Error(), "a, b") {
			t.Errorf("error should list the contexts in a stable order: %v", err)
		}
	})
	t.Run("unknown name", func(t *testing.T) {
		_, err := cfg.Context("c")
		if err == nil || !strings.Contains(err.Error(), "a, b") {
			t.Errorf("want an error listing the defined contexts, got: %v", err)
		}
	})
	t.Run("single context needs no default", func(t *testing.T) {
		one, derr := Decode([]byte("[context.only]\nou = \"ou-exam-research1\"\n"), "test.toml")
		if derr != nil {
			t.Fatalf("Decode: %v", derr)
		}
		ctx, cerr := one.Context("")
		if cerr != nil || ctx.OU != "ou-exam-research1" {
			t.Errorf("Context() = %+v, %v", ctx, cerr)
		}
	})
}

// TestLoadTreatsAMissingFileAsNoConfig: automat needs no configuration in
// STANDALONE or MANAGEMENT state, so demanding a file would block the two paths
// that can discover everything they need.
func TestLoadTreatsAMissingFileAsNoConfig(t *testing.T) {
	cfg, found, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if found {
		t.Error("found = true for a file that does not exist")
	}
	if cfg == nil || cfg.Contexts == nil {
		t.Error("Load must return a usable empty config, not a nil map to panic on later")
	}
}

func TestLoadReadsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(goodConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, found, err := Load(path)
	if err != nil || !found {
		t.Fatalf("Load = %v, found %v", err, found)
	}
	if cfg.DefaultContext != "research" {
		t.Errorf("DefaultContext = %q", cfg.DefaultContext)
	}
}

func TestDefaultPathHonorsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if got != "/tmp/xdg/automat/config.toml" {
		t.Errorf("DefaultPath = %q", got)
	}
}

// TestSSOStartURLIsRefusedInsecure covers the value that decides where a bearer
// token is exchanged. It is checked at load time rather than only in
// internal/login, so an operator running any command against a config with an
// http:// start URL is told before a credential is ever exchanged over it.
func TestSSOStartURLIsRefusedInsecure(t *testing.T) {
	for name, url := range map[string]string{
		"plain http":        "http://example.awsapps.com/start",
		"file scheme":       "file:///etc/passwd",
		"no scheme":         "example.awsapps.com/start",
		"no host":           "https:///start",
		"padded":            " https://example.awsapps.com/start ",
		"newline injection": "https://example.awsapps.com/start\nsso_region = \"evil\"",
	} {
		t.Run(name, func(t *testing.T) {
			doc := "[context.research]\nsso_start_url = " + strconv.Quote(url) + "\n"
			if _, err := Decode([]byte(doc), "test.toml"); err == nil {
				t.Errorf("Decode accepted sso_start_url %q", url)
			}
		})
	}
	// And the valid form still loads.
	doc := "[context.research]\nsso_start_url = \"https://example.awsapps.com/start\"\n" +
		"sso_region = \"us-east-1\"\n"
	if _, err := Decode([]byte(doc), "test.toml"); err != nil {
		t.Errorf("Decode rejected a valid SSO configuration: %v", err)
	}
}

// TestRegionMustLookLikeARegion: both region fields reach an SDK endpoint
// resolver. A value with a dot or a slash in it is one that has been mistaken for
// a hostname or a path somewhere upstream, and an endpoint built from it points
// somewhere the operator did not choose.
func TestRegionMustLookLikeARegion(t *testing.T) {
	for _, key := range []string{"region", "sso_region"} {
		for _, bad := range []string{
			"us-east-1.evil.example.com",
			"../us-east-1",
			"US-EAST-1",
			"us_east_1",
			"us-east-1/",
			"http://evil.example.com",
		} {
			doc := "[context.research]\n" + key + " = " + strconv.Quote(bad) + "\n"
			if _, err := Decode([]byte(doc), "test.toml"); err == nil {
				t.Errorf("Decode accepted %s = %q", key, bad)
			}
		}
		// Real region shapes, including the ones with three segments.
		for _, good := range []string{"us-east-1", "eu-west-2", "ap-southeast-4", "us-gov-west-1"} {
			doc := "[context.research]\n" + key + " = " + strconv.Quote(good) + "\n"
			if _, err := Decode([]byte(doc), "test.toml"); err != nil {
				t.Errorf("Decode rejected %s = %q, which is a real region: %v", key, good, err)
			}
		}
	}
}

// The tests below cover safeio.ReadConfig's structural refusals as reached through
// Load. They are here rather than only in internal/safeio because the reason they
// matter is a property of *this* file: it carries external_id_ref, and whoever
// chooses that reference chooses the ExternalId that the vendor role's trust policy
// requires. A symlink or a FIFO at the config path is that choice being made by
// someone else, and it does not touch the config file's own mode, so no permission
// check would notice.

// TestLoadRefusesAConfigThroughASymlink. os.Root follows a symlink whose target is
// inside the root and ignores O_NOFOLLOW, so nothing about resolving the directory
// safely refuses this on its own — the Lstat does. The target here is inside the same
// directory precisely because the escaping case is the easy one.
func TestLoadRefusesAConfigThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker.toml")
	if err := os.WriteFile(target, []byte(goodConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	_, found, err := Load(path)
	if err == nil {
		t.Fatal("a config read through a symlink was accepted; whoever controls the link " +
			"controls external_id_ref, and therefore the ExternalId")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("the error does not name the cause: %v", err)
	}
	// found must not be true: a symlink is a failure to read the config, not a
	// config that was found and rejected for its contents.
	if found {
		t.Error("found = true for a config that was never read")
	}
}

// TestLoadRefusesAFIFOConfigWithoutHanging. Opening a FIFO for reading blocks until a
// writer arrives, so a mode-0600 pipe the operator owns passes every permission check
// and hangs every automat command before it prints anything. The timeout is the
// assertion: a test that only checked the error would hang rather than fail if the
// refusal were dropped.
//
// Jam-checked, and the result is worth stating precisely rather than claiming more
// than it shows. Removing safeio.OpenNonBlock leaves this test passing: the FIFO is
// present before Load runs, so the pre-open Lstat's regular-file check refuses it and
// no open is ever attempted. Replacing the whole call with os.ReadFile fails it, after
// hanging the full 15 seconds — which is the behavior this covers. What O_NONBLOCK
// protects is the narrower case a static test cannot stage: a FIFO swapped in *after*
// the Lstat, where the open is the thing that blocks. Both checks are kept; only the
// first is what this test exercises.
func TestLoadRefusesAFIFOConfigWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := Load(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was accepted as a config file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("the error does not name the cause: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Load blocked on a FIFO at the config path — opening a pipe waits for the " +
			"other end, so every automat command hangs before printing anything")
	}
}

// TestLoadRefusesAConfigInAWorldWritableDirectory. The file's own mode proves nothing
// when anyone can replace the file: a 0600 config in a 0777 directory is a 0600 config
// that someone else can swap for theirs. Sticky is exempt, which is what keeps /tmp
// usable, and the second half of this test asserts that exemption rather than leaving
// it to be discovered by whoever finds automat refusing to run.
func TestLoadRefusesAConfigInAWorldWritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: the mode is advisory")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Explicit chmod: Mkdir's mode is filtered by umask, and a test that depends on
	// the umask it happens to run under is a test that passes on one machine.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(goodConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, _, err := Load(path); err == nil {
		t.Error("a config in a world-writable directory was accepted; anyone who can write " +
			"that directory can choose external_id_ref")
	} else if !strings.Contains(err.Error(), "writable beyond its owner") {
		t.Errorf("the error does not name the cause: %v", err)
	}

	// Sticky: /tmp is world-writable and legitimate, because sticky stops one user
	// removing or renaming another's entry.
	//
	// fs.ModeSticky, not 0o1777. os.Chmod takes an fs.FileMode, where the sticky bit
	// is a named flag well above the permission bits; the raw 0o1000 an operator
	// would type at a shell is silently dropped. Writing it the wrong way here made
	// this test assert the opposite of its own comment — it chmodded 0777 twice and
	// then reported that a sticky directory was refused.
	if err := os.Chmod(dir, 0o777|fs.ModeSticky); err != nil {
		t.Skipf("chmod sticky unsupported: %v", err)
	}
	if _, found, err := Load(path); err != nil || !found {
		t.Errorf("a config in a sticky world-writable directory was refused: %v", err)
	}
}

// TestLoadAcceptsAGroupReadableConfig is the counterweight to the tests above, and it
// is the reason ReadConfig exists as a sibling of ReadSecret rather than a call to it.
// This file is not a secret: it holds a *reference* to the ExternalId, not the value
// (DESIGN §13). An operator who keeps it group-readable so a colleague can see which
// org a context points at is doing something reasonable, and refusing it would push
// them toward keeping the real value somewhere worse.
func TestLoadAcceptsAGroupReadableConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(goodConfig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, found, err := Load(path)
	if err != nil {
		t.Fatalf("a group- and world-readable config was refused, which would be the wrong "+
			"rule for a file that holds a reference and not a value: %v", err)
	}
	if !found || cfg.DefaultContext != "research" {
		t.Errorf("found = %v, DefaultContext = %q", found, cfg.DefaultContext)
	}
}

// TestLoadRefusesAnOversizeConfig. The bound is not about a plausible config; it is
// that Load reads a path something else may control, and an unbounded read lets
// whatever writes that path decide how much memory automat uses. A refusal names the
// limit, because a truncated TOML file would fail to parse for a reason nobody
// would guess.
func TestLoadRefusesAnOversizeConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	big := goodConfig + "\n# " + strings.Repeat("x", maxConfigBytes)
	if err := os.WriteFile(path, []byte(big), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("a config larger than the limit was read in full")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("the error does not name the cause: %v", err)
	}
}
