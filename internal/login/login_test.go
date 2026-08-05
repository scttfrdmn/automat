// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"context"
	"crypto/sha1" //nolint:gosec // Matching the production interop hash on purpose.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

const (
	testStartURL = "https://example.awsapps.com/start"
	testRegion   = "us-east-1"
)

// testOptions returns options wired to a temp cache and a clock that does not
// sleep. Every test starts here, so a test that needs real time or a real home
// directory has to say so.
func testOptions(t *testing.T) Options {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	return Options{
		StartURL: testStartURL,
		Region:   testRegion,
		CacheDir: t.TempDir(),
		Sleep:    func(d time.Duration) { now = now.Add(d) },
		Now:      func() time.Time { return now },
	}
}

func TestLoginCachesTheTokenWhereTheSDKsRead(t *testing.T) {
	api := awsfake.NewSSOOIDC(0)
	opts := testOptions(t)

	res, err := Login(context.Background(), api, opts)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The filename is the interop contract. Computed here the way the AWS CLI
	// computes it rather than by calling cacheFileName, so this test fails if the
	// production hash is ever "upgraded" — which would produce a file automat
	// writes and nothing else reads, including `aws sso logout`.
	sum := sha1.Sum([]byte(testStartURL)) //nolint:gosec // See above.
	want := filepath.Join(opts.CacheDir, hex.EncodeToString(sum[:])+".json")
	if res.CachePath != want {
		t.Errorf("cached the token at %s, but the AWS CLI and SDKs look for %s — a token in the "+
			"wrong place is one no other tool can use and `aws sso logout` cannot clear",
			res.CachePath, want)
	}

	data, err := os.ReadFile(res.CachePath) //nolint:gosec // Path is from t.TempDir.
	if err != nil {
		t.Fatalf("read the cache: %v", err)
	}
	// Field names are part of the same contract; check them as JSON keys rather
	// than by unmarshaling into our own struct, which would pass even if the tags
	// were wrong in matching ways.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("the cache is not valid JSON, so no SDK can read it: %v", err)
	}
	for _, key := range []string{"startUrl", "region", "accessToken", "expiresAt"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("the cache has no %q key; the SDK credential chain requires it", key)
		}
	}
	if raw["accessToken"] != api.AccessToken {
		t.Errorf("cached access token is %v, want the one the provider returned", raw["accessToken"])
	}
	// The expiry must be RFC3339, or the SDK treats the token as unparseable.
	if _, err := time.Parse(time.RFC3339, raw["expiresAt"].(string)); err != nil {
		t.Errorf("expiresAt %q is not RFC3339, which is the format the SDKs parse: %v",
			raw["expiresAt"], err)
	}
}

// TestLoginWaitsThroughAuthorizationPending is the bug that makes a device flow
// useless: the first poll always comes back pending, because the operator has not
// finished clicking. An implementation that treats it as an error never logs
// anybody in.
func TestLoginWaitsThroughAuthorizationPending(t *testing.T) {
	api := awsfake.NewSSOOIDC(4)
	res, err := Login(context.Background(), api, testOptions(t))
	if err != nil {
		t.Fatalf("Login gave up on a pending authorization, which is the normal case for every "+
			"poll before the operator approves: %v", err)
	}
	if res.Polls != 5 {
		t.Errorf("took %d polls, want 5 (4 pending + 1 success)", res.Polls)
	}
}

// TestLoginBacksOffOnSlowDown checks the other RFC 8628 response that must not be
// treated as a failure — and must not be treated as "pending" either, since
// ignoring it gets the client throttled.
func TestLoginBacksOffOnSlowDown(t *testing.T) {
	api := awsfake.NewSSOOIDC(0)
	slowDowns := 2
	api.TokenErr = &awsfake.APIError{Code: "SlowDownException", Message: "slow down"}

	var slept []time.Duration
	opts := testOptions(t)
	opts.Sleep = func(d time.Duration) {
		slept = append(slept, d)
		if len(slept) >= slowDowns {
			api.TokenErr = nil // The operator finishes approving.
		}
	}

	if _, err := Login(context.Background(), api, opts); err != nil {
		t.Fatalf("Login treated SlowDown as fatal: %v", err)
	}
	if len(slept) < slowDowns {
		t.Fatalf("slept %d times, want at least %d", len(slept), slowDowns)
	}
	// Each SlowDown must lengthen the interval, not keep it flat.
	for i := 1; i < len(slept); i++ {
		if slept[i] <= slept[i-1] {
			t.Errorf("poll interval did not increase after SlowDown: %v then %v — ignoring the "+
				"backoff signal is how a client gets throttled and the login fails for no "+
				"visible reason", slept[i-1], slept[i])
		}
	}
	// And it must be capped, or a long enough sequence sleeps for hours.
	for _, d := range slept {
		if d > maxPollInterval {
			t.Errorf("slept %v, which exceeds the %v cap", d, maxPollInterval)
		}
	}
}

// TestEachTerminalErrorGetsItsOwnRemediation is CLAUDE.md rule 7 applied to the
// login path. These four responses mean different things and have different fixes;
// one generic "login failed" makes the operator guess.
func TestEachTerminalErrorGetsItsOwnRemediation(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
		// want is a phrase that must appear, and mustNot one that must not.
		want    string
		mustNot string
	}{
		{
			name: "expired code says run it again",
			code: "ExpiredTokenException",
			want: "again",
		},
		{
			name: "denied does not tell them to retry",
			code: "AccessDeniedException",
			want: "denied",
			// Retrying a denial is wrong, so the message must not suggest it.
			mustNot: "try again",
		},
		{
			name: "an unmodeled error is passed through rather than guessed at",
			code: "SomethingNobodyAnticipated",
			want: "SomethingNobodyAnticipated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := awsfake.NewSSOOIDC(0)
			api.TokenErr = &awsfake.APIError{Code: tc.code, Message: "from the provider"}

			_, err := Login(context.Background(), api, testOptions(t))
			if err == nil {
				t.Fatalf("%s did not fail the login", tc.code)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error for %s does not mention %q, so the operator cannot tell what to "+
					"do next: %v", tc.code, tc.want, msg)
			}
			if tc.mustNot != "" && strings.Contains(strings.ToLower(msg), tc.mustNot) {
				t.Errorf("error for %s suggests %q, which is the wrong advice: %v",
					tc.code, tc.mustNot, msg)
			}
		})
	}
}

// TestNoErrorPathLeaksTheToken is the credential-leak check. Every failure after
// the token is in hand must describe the failure without quoting the credential —
// an error message ends up in scrollback, CI logs, and pasted issue reports.
func TestNoErrorPathLeaksTheToken(t *testing.T) {
	const secret = "SECRET-BEARER-TOKEN-DO-NOT-PRINT"

	// A cache directory that cannot be written, so writeCache fails with the
	// token already fetched — the only window where a leak is possible.
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based unwritable directory is not portable to Windows")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	api := awsfake.NewSSOOIDC(0)
	api.AccessToken = secret
	opts := testOptions(t)
	opts.CacheDir = dir

	_, err := Login(context.Background(), api, opts)
	if err == nil {
		t.Skip("the unwritable directory did not stop the write; nothing to assert")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error message contains the access token. Errors reach scrollback, CI logs, "+
			"and pasted issue reports:\n%v", err)
	}
}

// TestResultDoesNotCarryTheToken is the same concern one level up. A caller that
// prints or logs the Result struct — which is a normal thing to do — must not be
// able to print a credential by accident.
func TestResultDoesNotCarryTheToken(t *testing.T) {
	const secret = "SECRET-BEARER-TOKEN-DO-NOT-PRINT"
	api := awsfake.NewSSOOIDC(0)
	api.AccessToken = secret

	res, err := Login(context.Background(), api, testOptions(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// %+v on the struct, and the String method the CLI actually calls.
	for name, s := range map[string]string{
		"the struct printed with %+v": fmt.Sprintf("%+v", *res),
		"Result.String":               res.String(),
	} {
		if strings.Contains(s, secret) {
			t.Errorf("%s contains the access token:\n%s", name, s)
		}
	}
	// And it should point at `aws sso logout`, since the token it just wrote is
	// shared with every other AWS tool on the machine and the operator should
	// know that.
	if !strings.Contains(res.String(), "logout") {
		t.Error("Result.String does not mention how to clear the token it just cached")
	}
}

func TestCachedTokenIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	res, err := Login(context.Background(), awsfake.NewSSOOIDC(0), testOptions(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	fi, err := os.Stat(res.CachePath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != cacheFileMode {
		t.Errorf("the token cache is mode %o, want %o — this file is a live bearer token",
			got, cacheFileMode)
	}
}

// TestLoginTightensALooseCacheDirectory covers the pre-existing directory: a
// ~/.aws/sso/cache left group-readable by an older tool is a directory full of
// bearer tokens that other accounts on the machine can read.
func TestLoginTightensALooseCacheDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	opts := testOptions(t)
	opts.CacheDir = dir

	if _, err := Login(context.Background(), awsfake.NewSSOOIDC(0), opts); err != nil {
		t.Fatalf("Login: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != cacheDirMode {
		t.Errorf("the cache directory is still mode %o, want %o — it holds bearer tokens for "+
			"every SSO instance this machine has logged into", got, cacheDirMode)
	}
}

// TestLoginRefusesToWriteACredentialThroughASymlink is the sharp one. Anything
// that can write into ~/.aws/sso/cache can plant a symlink at the filename
// automat is about to write, and automat would then deliver a live bearer token
// wherever the link points.
// The tests from here to TestLoginRefusesADirectoryInTheCacheFilesPlace cover
// writeCache's defenses against something that can already write into
// ~/.aws/sso/cache. Those defenses overlap, so no single test proves any single
// check is present. Jam-checked one at a time, with the patch confirmed applied:
//
//	pre-open symlink branch, alone ....... nothing fails
//	pre-open IsRegular, alone ............ nothing fails
//	both pre-open name checks ............ nothing fails
//	both + the os.SameFile tie ........... the in-directory symlink test fails
//	both + O_NONBLOCK .................... the FIFO test fails
//	the os.SameFile tie, alone ........... nothing fails
//	safeio.LinkCount, alone .............. the hardlink test fails
//
// Read that as: os.SameFile is the last line for a symlink and O_NONBLOCK is the
// last line for a FIFO, the two pre-open name checks are redundant with them and
// with each other, and LinkCount is the only thing standing between a hardlink and
// a copied bearer token. The pre-open checks are kept even so — they refuse before
// the open rather than after, which for a FIFO is the difference between an error
// and having opened one, and they are what produce the message that names the fix.
// The redundancy is deliberate; recording it here is so a later reader does not
// mistake "every test passes" for "every check is load-bearing".
func TestLoginRefusesToWriteACredentialThroughASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "stolen.json")
	sum := sha1.Sum([]byte(testStartURL)) //nolint:gosec // Interop hash.
	target := filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	opts := testOptions(t)
	opts.CacheDir = dir
	const secret = "SECRET-BEARER-TOKEN-DO-NOT-PRINT"
	api := awsfake.NewSSOOIDC(0)
	api.AccessToken = secret

	_, err := Login(context.Background(), api, opts)
	if err == nil {
		t.Fatal("Login wrote through a symlink at the cache path — a planted link there " +
			"redirects a live bearer token to wherever it points")
	}
	if _, serr := os.Stat(outside); serr == nil {
		t.Error("the symlink target was created, so the token was written outside the cache")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal message leaks the token: %v", err)
	}
}

// TestLoginRefusesASymlinkPointingInsideTheCacheDirectory is the case os.Root does
// not cover, and the reason this defense cannot be left to it.
//
// Verified against go1.24 on darwin: os.Root refuses a symlink whose target
// *escapes* the root, which is what the test above plants — but it *follows* one
// whose target is inside the root, and it silently ignores syscall.O_NOFOLLOW in
// the flags it is passed. So a link to a sibling path is followed, and a check made
// against the opened descriptor sees the target: a perfectly regular file.
//
// The consequence here is not an escaped write but a chosen one. Anything that can
// write into ~/.aws/sso/cache can point automat's filename at a second file it
// keeps, and then read the bearer token out of it after automat has written it —
// including after `aws sso logout`, which clears the name automat wrote, not the
// name the token landed in.
func TestLoginRefusesASymlinkPointingInsideTheCacheDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	dir := t.TempDir()
	sum := sha1.Sum([]byte(testStartURL)) //nolint:gosec // Interop hash.
	name := hex.EncodeToString(sum[:]) + ".json"

	// The attacker's file, inside the same directory, so os.Root permits it.
	sibling := filepath.Join(dir, "attacker-keeps-this.json")
	if err := os.WriteFile(sibling, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	if err := os.Symlink("attacker-keeps-this.json", filepath.Join(dir, name)); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	opts := testOptions(t)
	opts.CacheDir = dir
	const secret = "SECRET-BEARER-TOKEN-DO-NOT-PRINT"
	api := awsfake.NewSSOOIDC(0)
	api.AccessToken = secret

	_, err := Login(context.Background(), api, opts)
	if err == nil {
		t.Fatal("Login wrote a bearer token through a symlink to a file in the same directory")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal message leaks the token: %v", err)
	}
	got, rerr := os.ReadFile(sibling) //nolint:gosec // test fixture
	if rerr != nil {
		t.Fatalf("read sibling: %v", rerr)
	}
	if strings.Contains(string(got), secret) {
		t.Error("the bearer token was written into the symlink's target, where `aws sso logout` " +
			"will not clear it")
	}
}

// TestLoginRefusesAHardlinkedCacheEntry. A hardlink passes every check a symlink
// fails: Lstat reports a regular file, no path is escaped, and the mode is
// whatever the attacker set. Only the link count distinguishes it, and writing
// through one copies a live bearer token into a second name the attacker keeps.
//
// Unlike the symlink and FIFO cases above, nothing else covers this one: disabling
// safeio.LinkCount fails this test and only this test. It is the single defense.
func TestLoginRefusesAHardlinkedCacheEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hardlink semantics")
	}
	dir := t.TempDir()
	sum := sha1.Sum([]byte(testStartURL)) //nolint:gosec // Interop hash.
	name := filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	attackers := filepath.Join(dir, "attackers-second-name.json")
	if err := os.Link(name, attackers); err != nil {
		t.Skipf("hardlink unsupported: %v", err)
	}

	opts := testOptions(t)
	opts.CacheDir = dir
	const secret = "SECRET-BEARER-TOKEN-DO-NOT-PRINT"
	api := awsfake.NewSSOOIDC(0)
	api.AccessToken = secret

	_, err := Login(context.Background(), api, opts)
	if err == nil {
		t.Fatal("Login wrote a bearer token into a file with two names")
	}
	if !strings.Contains(err.Error(), "hard link") {
		t.Errorf("the error should say what it refused and why: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal message leaks the token: %v", err)
	}
	got, rerr := os.ReadFile(attackers) //nolint:gosec // test fixture
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if strings.Contains(string(got), secret) {
		t.Error("the token was written into the attacker's second name for the same inode")
	}
}

// TestLoginRefusesAFIFOAtTheCachePathWithoutHanging was found by jam-checking this
// package: removing the descriptor's regular-file check did not fail any test,
// which meant nothing reached it.
//
// It could not be reached. Opening a FIFO for *writing* blocks until a reader
// arrives, so `automat login` against a mode-0600 pipe the operator owns hung
// indefinitely, with no output, holding a live bearer token in memory — a denial of
// service that reads as a network stall, planted by anything that can write into
// ~/.aws/sso/cache. The timeout below is the assertion: a test that only checked
// the error would hang rather than fail if the fix were reverted.
//
// Two defenses now cover a FIFO planted before the check — the pre-open refusal and
// O_NONBLOCK — so removing either alone still passes. Removing both hangs, and this
// test then fails on the timeout rather than stalling the package. So this does not
// prove the flag is present; it proves the pair is.
func TestLoginRefusesAFIFOAtTheCachePathWithoutHanging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs")
	}
	dir := t.TempDir()
	sum := sha1.Sum([]byte(testStartURL)) //nolint:gosec // Interop hash.
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
	if err := mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	opts := testOptions(t)
	opts.CacheDir = dir
	const secret = "SECRET-BEARER-TOKEN-DO-NOT-PRINT"
	api := awsfake.NewSSOOIDC(0)
	api.AccessToken = secret

	done := make(chan error, 1)
	go func() {
		_, err := Login(context.Background(), api, opts)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was accepted as the token cache")
		}
		if !strings.Contains(err.Error(), "logout") {
			t.Errorf("the error should say how to clear the cache: %v", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the refusal message leaks the token: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Login blocked on a FIFO at the cache path — opening a pipe for writing waits " +
			"for a reader, so this hangs with a live token in memory and no output")
	}
}

// TestLoginRefusesASymlinkedCacheDirectory. The file checks above are moot if the
// directory itself is a link: the token still lands wherever it points, and
// `aws sso logout` still clears the wrong place.
func TestLoginRefusesASymlinkedCacheDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	base := t.TempDir()
	real := filepath.Join(base, "attackers-dir")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "cache")
	if err := os.Symlink("attackers-dir", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	opts := testOptions(t)
	opts.CacheDir = link
	const secret = "SECRET-BEARER-TOKEN-DO-NOT-PRINT"
	api := awsfake.NewSSOOIDC(0)
	api.AccessToken = secret

	_, err := Login(context.Background(), api, opts)
	if err == nil {
		t.Fatal("Login wrote a bearer token into a symlinked cache directory")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal message leaks the token: %v", err)
	}
	entries, rerr := os.ReadDir(real)
	if rerr != nil {
		t.Fatalf("readdir: %v", rerr)
	}
	if len(entries) != 0 {
		t.Errorf("%d file(s) landed in the symlink's target", len(entries))
	}
}

// TestLoginRefusesADirectoryInTheCacheFilesPlace is the same defense against a
// non-symlink obstruction, which otherwise surfaces as a confusing write error.
func TestLoginRefusesADirectoryInTheCacheFilesPlace(t *testing.T) {
	dir := t.TempDir()
	sum := sha1.Sum([]byte(testStartURL)) //nolint:gosec // Interop hash.
	if err := os.Mkdir(filepath.Join(dir, hex.EncodeToString(sum[:])+".json"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	opts := testOptions(t)
	opts.CacheDir = dir

	_, err := Login(context.Background(), awsfake.NewSSOOIDC(0), opts)
	if err == nil {
		t.Fatal("Login did not refuse a directory in the cache file's place")
	}
	if !strings.Contains(err.Error(), "logout") {
		t.Errorf("the error does not say how to clear the cache, which is the fix: %v", err)
	}
}

// TestStartURLMustBeHTTPS refuses a downgrade on the exchange that carries the
// bearer token. The start URL is operator-supplied and also decides the cache
// filename, so it is worth being strict about.
func TestStartURLMustBeHTTPS(t *testing.T) {
	for _, bad := range []string{
		"http://example.awsapps.com/start",
		"file:///etc/passwd",
		"ftp://example.com/start",
		"example.awsapps.com/start", // No scheme at all.
		"",
		"  https://example.awsapps.com/start  ", // Padded: reads as valid, is not.
	} {
		opts := testOptions(t)
		opts.StartURL = bad
		if _, err := Login(context.Background(), awsfake.NewSSOOIDC(0), opts); err == nil {
			t.Errorf("Login accepted start URL %q", bad)
		}
	}
}

// TestNoNetworkCallBeforeTheOptionsAreChecked matters because RegisterClient is a
// side effect: it creates a client registration at the provider. Validating after
// the first call means a bad invocation still leaves something behind.
func TestNoNetworkCallBeforeTheOptionsAreChecked(t *testing.T) {
	api := awsfake.NewSSOOIDC(0)
	opts := testOptions(t)
	opts.StartURL = "http://insecure.example.com/start"

	if _, err := Login(context.Background(), api, opts); err == nil {
		t.Fatal("expected the insecure start URL to be refused")
	}
	if calls := api.Calls(); len(calls) != 0 {
		t.Errorf("automat called %v before validating its options; RegisterClient creates a "+
			"registration at the provider, so a rejected invocation should leave nothing behind",
			calls)
	}
}

func TestRegistrationAsksForNoScopeBeyondWhatItNeeds(t *testing.T) {
	api := awsfake.NewSSOOIDC(0)
	if _, err := Login(context.Background(), api, testOptions(t)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if api.LastRegister == nil {
		t.Fatal("no registration recorded")
	}
	want := []string{"sso:account:access"}
	if got := api.LastRegister.Scopes; len(got) != 1 || got[0] != want[0] {
		t.Errorf("registered with scopes %v, want exactly %v — a token is only as narrow as the "+
			"scopes it carries, and automat only lists accounts and fetches role credentials",
			got, want)
	}
}

// TestScopesCannotInjectAnotherScope: scopes are space-delimited in the protocol,
// so a value containing a space is two scopes. Nothing in automat sets them today,
// but the field is exported and reachable from config.
func TestScopesCannotInjectAnotherScope(t *testing.T) {
	for _, bad := range []string{
		"sso:account:access sso:something:else",
		"sso:account:access\nsso:other",
		"sso:account:access\tmore",
		`sso:account:access"`,
		"",
	} {
		opts := testOptions(t)
		opts.Scopes = []string{bad}
		if _, err := Login(context.Background(), awsfake.NewSSOOIDC(0), opts); err == nil {
			t.Errorf("Login accepted scope %q, which is more than one scope", bad)
		}
	}
}

// TestLoginStopsWhenTheContextIsCancelled: an operator who hits Ctrl-C, or a CI
// job that times out, must not leave automat polling.
func TestLoginStopsWhenTheContextIsCancelled(t *testing.T) {
	api := awsfake.NewSSOOIDC(100) // Never approves.
	ctx, cancel := context.WithCancel(context.Background())

	opts := testOptions(t)
	polls := 0
	opts.Sleep = func(time.Duration) {
		polls++
		if polls == 3 {
			cancel()
		}
	}

	_, err := Login(ctx, api, opts)
	if err == nil {
		t.Fatal("Login ignored a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error does not wrap context.Canceled, so a caller cannot distinguish an "+
			"operator's Ctrl-C from a real failure: %v", err)
	}
}

// TestLoginGivesUpBeforeTheCodeExpires stops `automat login` from hanging forever
// in a script when nobody is at the browser.
func TestLoginGivesUpBeforeTheCodeExpires(t *testing.T) {
	api := awsfake.NewSSOOIDC(1_000_000) // Never approves.
	opts := testOptions(t)
	if _, err := Login(context.Background(), api, opts); err == nil {
		t.Fatal("Login polled forever against an authorization that is never approved")
	}
	// The fake reports ExpiresIn=600 and Interval=1, so it must stop well before
	// a thousand polls.
	if n := len(api.Calls()); n > 700 {
		t.Errorf("made %d calls before giving up; the device code's own expiry should have "+
			"stopped it around 600", n)
	}
}

// TestProviderFaultsAreNotSilentlyTreatedAsSuccess covers the missing-field cases.
// A nil AccessToken with a nil error would otherwise write a cache file containing
// an empty credential, which fails later somewhere much less obvious.
func TestProviderFaultsAreNotSilentlyTreatedAsSuccess(t *testing.T) {
	t.Run("no access token", func(t *testing.T) {
		api := &emptyTokenSSOOIDC{SSOOIDC: awsfake.NewSSOOIDC(0)}
		opts := testOptions(t)
		if _, err := Login(context.Background(), api, opts); err == nil {
			t.Fatal("Login accepted an approval with no access token")
		}
		entries, _ := os.ReadDir(opts.CacheDir)
		if len(entries) != 0 {
			t.Errorf("wrote %d cache file(s) for a token that does not exist", len(entries))
		}
	})
}

// emptyTokenSSOOIDC returns a successful CreateToken with no token in it — the
// shape a provider fault takes, and one the fake cannot produce on its own.
type emptyTokenSSOOIDC struct {
	*awsfake.SSOOIDC
}

func (f *emptyTokenSSOOIDC) CreateToken(_ context.Context, _ *ssooidc.CreateTokenInput,
	_ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	return &ssooidc.CreateTokenOutput{TokenType: aws.String("Bearer")}, nil
}

// TestPromptShowsBothTheURLAndTheCode. The code is not decoration: it is how the
// operator verifies the page they landed on belongs to the request they made,
// which is the only defense this flow has against being phished into approving
// somebody else's login.
func TestPromptShowsBothTheURLAndTheCode(t *testing.T) {
	var got Prompt
	opts := testOptions(t)
	opts.Prompt = func(p Prompt) { got = p }

	if _, err := Login(context.Background(), awsfake.NewSSOOIDC(2), opts); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got.UserCode == "" || got.VerificationURI == "" {
		t.Fatalf("prompt is incomplete: %+v", got)
	}
	s := got.String()
	for _, want := range []string{got.UserCode, got.VerificationURI} {
		if !strings.Contains(s, want) {
			t.Errorf("the prompt does not show %q:\n%s", want, s)
		}
	}
	// The verification page must be named even when the complete URL exists, so
	// the operator has a path that survives a wrapped terminal line.
	if got.VerificationURIComplete != "" && !strings.Contains(s, got.VerificationURI) {
		t.Error("the prompt offers only the one-click URL; a terminal that wraps it leaves the " +
			"operator with nothing to type")
	}
	if !strings.Contains(strings.ToLower(s), "check that the page shows the code") {
		t.Error("the prompt does not tell the operator to verify the code on the page, which is " +
			"the only check that distinguishes their own login from one they were phished into")
	}
}

// TestPromptIsShownBeforeTheFirstPoll: a login that computes the prompt but does
// not hand it over until the flow finishes is a login that appears to hang, and
// the operator never sees the code they are being asked to confirm.
func TestPromptIsShownBeforeTheFirstPoll(t *testing.T) {
	api := awsfake.NewSSOOIDC(3)
	opts := testOptions(t)
	prompted := -1
	opts.Prompt = func(Prompt) { prompted = len(api.Calls()) }

	if _, err := Login(context.Background(), api, opts); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if prompted < 0 {
		t.Fatal("the operator was never prompted")
	}
	// Two calls so far: RegisterClient and StartDeviceAuthorization. Any
	// CreateToken before the prompt means time spent waiting on an operator who
	// has not been told what to do.
	if prompted != 2 {
		t.Errorf("prompted after %d API calls, want 2 (register + start) — polling before the "+
			"operator sees the code is a login that looks like a hang", prompted)
	}
}

func TestReloginReplacesTheCachedToken(t *testing.T) {
	opts := testOptions(t)

	first := awsfake.NewSSOOIDC(0)
	first.AccessToken = "first-token"
	r1, err := Login(context.Background(), first, opts)
	if err != nil {
		t.Fatalf("first Login: %v", err)
	}

	second := awsfake.NewSSOOIDC(0)
	second.AccessToken = "second-token"
	r2, err := Login(context.Background(), second, opts)
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	if r1.CachePath != r2.CachePath {
		t.Errorf("the same start URL cached to two different files (%s, %s); the credential "+
			"chain would read whichever it found and the other would be a stale token nobody "+
			"can log out of", r1.CachePath, r2.CachePath)
	}

	data, err := os.ReadFile(r2.CachePath) //nolint:gosec // Path is from t.TempDir.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "first-token") {
		t.Error("the old token survives in the cache file; O_TRUNC is what keeps a shorter new " +
			"token from leaving the tail of a longer old one behind")
	}
	if !strings.Contains(string(data), "second-token") {
		t.Error("the new token is not in the cache")
	}
}

// TestDifferentStartURLsGetDifferentCacheEntries: an operator with two SSO
// instances must not have one login evict the other, which is what a fixed
// filename would do.
func TestDifferentStartURLsGetDifferentCacheEntries(t *testing.T) {
	dir := t.TempDir()
	for _, u := range []string{
		"https://one.awsapps.com/start",
		"https://two.awsapps.com/start",
	} {
		opts := testOptions(t)
		opts.CacheDir = dir
		opts.StartURL = u
		if _, err := Login(context.Background(), awsfake.NewSSOOIDC(0), opts); err != nil {
			t.Fatalf("Login(%s): %v", u, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("two start URLs produced %d cache entries, want 2 — one login evicting the "+
			"other is a tool that logs you out of the org you were not working on", len(entries))
	}
}
