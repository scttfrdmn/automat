// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The golden files are the ROADMAP's Phase 1 accept criterion, and they are here
// for a reason beyond regression: these five files are the security boundary
// between a research group and a management account. A change to any byte of them
// changes what central IT is asked to grant, so it must show up as a diff a human
// approves rather than as a quietly different template.
//
// Two scenarios, because the bundle has one branch that matters:
//
//	member-existing-ou/  the OU exists and the trust principal is one role — the
//	                     narrow, everything-in-place case
//	member-new-ou/       the OU must be created and the whole account is trusted —
//	                     the widest form automat will emit, so the one worth
//	                     reviewing most carefully
//
// Update with AUTOMAT_UPDATE_GOLDEN=1, the same convention gen/catalog uses (a
// flag defined in one package makes `go test ./...` fail in every other).
const updateGoldenEnv = "AUTOMAT_UPDATE_GOLDEN"

func updateGolden() bool { return os.Getenv(updateGoldenEnv) == "1" }

// goldenScenarios are the request shapes the golden files cover. Fixed values
// throughout: nothing here may vary between runs, or the golden test becomes noise
// and gets ignored, which is the failure mode that matters.
var goldenScenarios = []struct {
	dir     string
	request func() *Request
}{
	{
		dir: "member-existing-ou",
		request: func() *Request {
			r := validRequest()
			r.MemberRoleARN = "arn:aws:iam::222222222222:role/automat-runner"
			return r
		},
	},
	{
		dir: "member-new-ou",
		request: func() *Request {
			r := validRequest()
			r.TargetOU = ""
			r.TargetOUName = "Research Computing"
			r.VendorRoleName = "automat-vendor-research"
			return r
		},
	},
}

// externalIDLike returns the first value in s that looks like an ExternalId automat
// generated but is not the test constant, or "" if there is none.
//
// It matches on the shape NewExternalID produces -- the automat- prefix followed by a
// long run of base32 -- because that is what a maintainer who regenerated these
// fixtures from a live configuration would have committed. Deliberately narrow: the
// goal is to catch the one realistic accident, not to guess at every possible secret.
func externalIDLike(s string) string {
	for _, m := range reGeneratedExternalID.FindAllString(s, -1) {
		if m != testExternalID {
			return m
		}
	}
	return ""
}

var reGeneratedExternalID = regexp.MustCompile(`automat-[A-Z2-7]{16,}`)

func TestBundleMatchesGolden(t *testing.T) {
	for _, sc := range goldenScenarios {
		t.Run(sc.dir, func(t *testing.T) {
			dir := filepath.Join("testdata", "golden", sc.dir)
			if updateGolden() {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for _, rd := range renderers {
				got, err := rd.render(sc.request())
				if err != nil {
					t.Fatalf("%s: %v", rd.name, err)
				}
				path := filepath.Join(dir, rd.name)
				if updateGolden() {
					// 0644: a golden file is a committed, reviewed artifact meant
					// to be read by anyone reviewing the grant — AUDIT-0 A2's
					// argument, and the ExternalId here is the fake test one.
					if werr := os.WriteFile(path, got, 0o644); werr != nil { //nolint:gosec // reviewed, committed fixture
						t.Fatalf("write %s: %v", path, werr)
					}
					t.Logf("updated %s (%d bytes)", path, len(got))
					continue
				}
				want, err := os.ReadFile(path) //nolint:gosec // fixed testdata path
				if err != nil {
					t.Fatalf("read %s: %v — run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/bundle/`",
						path, err)
				}
				if string(got) != string(want) {
					t.Errorf("%s does not match %s.\n%s\n"+
						"If the change is intended, run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/bundle/` "+
						"and review the diff: these files are what central IT is asked to grant.",
						rd.name, path, firstDiff(string(want), string(got)))
				}
			}
		})
	}
}

// firstDiff reports the first differing line, since a whole-file dump of a
// 200-line template hides the one line that changed.
func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return "first difference at line " + itoa(i+1) + ":\n  golden: " + w + "\n  now:    " + g
		}
	}
	return "the files differ only in trailing bytes"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestGoldenFilesCoverEveryFileAndScenario stops a renderer or a scenario from
// being added without a golden file, which would make the accept criterion
// partially true — the worst kind.
func TestGoldenFilesCoverEveryFileAndScenario(t *testing.T) {
	if updateGolden() {
		t.Skip("writing golden files")
	}
	root := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			onDisk[e.Name()] = true
		}
	}
	for _, sc := range goldenScenarios {
		if !onDisk[sc.dir] {
			t.Errorf("scenario %s has no golden directory", sc.dir)
		}
		delete(onDisk, sc.dir)

		files, err := os.ReadDir(filepath.Join(root, sc.dir))
		if err != nil {
			t.Fatal(err)
		}
		present := map[string]bool{}
		for _, f := range files {
			present[f.Name()] = true
		}
		for _, name := range FileNames() {
			if !present[name] {
				t.Errorf("%s/%s is missing", sc.dir, name)
			}
			delete(present, name)
		}
		for extra := range present {
			t.Errorf("%s/%s is a golden file with no renderer — a stale artifact from a "+
				"removed file", sc.dir, extra)
		}
	}
	for extra := range onDisk {
		t.Errorf("testdata/golden/%s has no scenario", extra)
	}
}

// TestGoldenFilesContainNoRealIdentifier is the tripwire against the mistake this
// kind of fixture invites: golden files are generated by running the tool, and a
// maintainer who regenerates them from a live configuration would commit a real
// account id, a real OU, and a real ExternalId to a public repository.
func TestGoldenFilesContainNoRealIdentifier(t *testing.T) {
	// The only account ids, org id, OU, and contact that may appear are the
	// documentation-reserved test values this package defines.
	allowed := map[string]bool{
		testMember: true, testManagement: true,
		"999999999999": true, // used in a negative test
	}
	for _, sc := range goldenScenarios {
		dir := filepath.Join("testdata", "golden", sc.dir)
		for _, name := range FileNames() {
			data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // fixed testdata path
			if err != nil {
				t.Fatalf("read %s/%s: %v", sc.dir, name, err)
			}
			s := string(data)
			// Any 12-digit run is an account id.
			for _, m := range twelveDigitRuns(s) {
				if !allowed[m] {
					t.Errorf("%s/%s contains the account id %s, which is not one of this "+
						"package's test values — was this regenerated from a live configuration?",
						sc.dir, name, m)
				}
			}
			if strings.Contains(s, "@") && !strings.Contains(s, "example.edu") &&
				!strings.Contains(s, "_+=,.@") {
				t.Errorf("%s/%s contains an address outside example.edu", sc.dir, name)
			}
			// This checks the FILE, not the constant. The previous version read
			// `strings.Contains(s, testExternalID) && !strings.Contains(testExternalID,
			// "EXAMPLE")` -- testExternalID is a compile-time constant containing
			// "EXAMPLE", so the second half was permanently false and the whole clause
			// was unreachable. It also tested the fake value rather than the file's
			// contents, so it could not have detected a real ExternalId even if it ran.
			// Jam-checked by planting a realistic value in a golden fixture.
			if jam := externalIDLike(s); jam != "" && !strings.Contains(s, testExternalID) {
				t.Errorf("%s/%s contains %q, which looks like a real ExternalId. These "+
					"fixtures are committed: regenerate them from the test request, not from "+
					"a live configuration.", sc.dir, name, jam)
			}
			for _, real := range []string{"amazonaws.com/console", "signin.aws.amazon.com"} {
				if strings.Contains(s, real) {
					t.Errorf("%s/%s contains %q", sc.dir, name, real)
				}
			}
		}
	}
}

func twelveDigitRuns(s string) []string {
	var out []string
	run := 0
	for i := 0; i <= len(s); i++ {
		digit := i < len(s) && s[i] >= '0' && s[i] <= '9'
		if digit {
			run++
			continue
		}
		if run == 12 {
			out = append(out, s[i-12:i])
		}
		run = 0
	}
	return out
}
