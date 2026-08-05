// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package login runs the AWS SSO device authorization grant and caches the token
// where the AWS SDKs already look for it.
//
// Its role in the vend pipeline is to be the step before preflight: everything
// downstream reads credentials from the standard AWS credential chain, and this is
// the one command that puts something into it. DESIGN §13 is deliberate that
// `login` is a convenience over the chain rather than a replacement for it — an
// operator with a working profile, an instance role, or a federated session should
// never need to run it.
//
// # Why automat writes the SDK's cache file rather than its own
//
// DESIGN §13 says: never store secrets; lean on the AWS credential chain and the
// OS keychain if anything must persist. A bearer token must persist — the whole
// point of a device flow is to not re-approve in a browser every thirty seconds —
// so the question is where.
//
// automat writes ~/.aws/sso/cache/<sha1(startUrl)>.json, the location the AWS CLI
// and every AWS SDK read. Not because it is the most secure option, but because
// the alternative is worse in a way that matters more:
//
//   - An automat-owned token store would be a second copy of a credential, with
//     automat's own lifetime and revocation semantics. Two caches means one of
//     them is stale, and a stale bearer token is one an operator believes they
//     have logged out of.
//   - `aws sso logout` clears this location. If automat kept its own, logout
//     would silently not cover it, and an operator's mental model of "I logged
//     out" would be wrong. That is a worse security property than the file mode.
//   - Every other command reads credentials through the chain, which reads this
//     file. A private store would need automat to inject credentials by hand,
//     which is a much larger blast radius than writing one file.
//
// So: one cache, the shared one, 0600, in a 0700 directory, written through
// os.Root for the same reason internal/bundle does. The file is a real credential
// and the package treats it as one — it is never logged, never printed, and never
// included in an error message.
package login

import (
	"context"
	"crypto/sha1" //nolint:gosec // Not a security decision: see cacheFileName.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/smithy-go"

	"github.com/scttfrdmn/automat/internal/awsapi"
	"github.com/scttfrdmn/automat/internal/safeio"
)

// The client automat registers itself as. RegisterClient takes a name purely for
// display in the approval screen and in CloudTrail; it is not an identity.
const (
	clientName = "automat"
	clientType = "public"
	// grantType is the device authorization grant, per RFC 8628.
	grantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// File modes. The cache holds a bearer token; the directory holds several.
const (
	cacheDirMode  = 0o700
	cacheFileMode = 0o600
)

// Poll bounds. The SDK reports a suggested interval and an expiry, both of which
// are honored — these are the guardrails around a server that reports something
// unusable.
const (
	minPollInterval = 1 * time.Second
	maxPollInterval = 30 * time.Second
	// defaultPollInterval is used when StartDeviceAuthorization reports none.
	defaultPollInterval = 5 * time.Second
	// maxFlowDuration caps the whole wait even if the server's ExpiresIn is
	// absurd, so `automat login` in a script cannot hang forever.
	maxFlowDuration = 15 * time.Minute
)

// Prompt is what the operator must be shown to complete the flow: the URL to
// open and the code to confirm. It is returned to the caller rather than printed
// here, so the CLI owns presentation and tests can assert on values.
type Prompt struct {
	// VerificationURI is the page the operator opens.
	VerificationURI string
	// VerificationURIComplete has the code embedded. Present it as the primary
	// path when available — it is one click rather than a transcription — but
	// never as the only path, because it does not survive being copied out of a
	// terminal that wrapped it.
	VerificationURIComplete string
	// UserCode is what the operator confirms on screen. Showing it matters even
	// when VerificationURIComplete exists: it is how the operator knows the page
	// they landed on belongs to the request they made.
	UserCode string
	// ExpiresIn is how long the code is valid.
	ExpiresIn time.Duration
}

// Options configures a login.
type Options struct {
	// StartURL is the SSO start URL, e.g. https://example.awsapps.com/start.
	StartURL string
	// Region is the SSO region — the region the identity store lives in, which
	// is not necessarily the region accounts are vended into.
	Region string
	// Scopes requested at registration. Empty means the default,
	// sso:account:access, which is what assuming a role through SSO requires.
	// Anything beyond it must be justified: a token is only as narrow as the
	// scopes it carries.
	Scopes []string

	// CacheDir overrides ~/.aws/sso/cache. Tests set it; operators should not
	// need to, since the whole point is to write where the SDKs read.
	CacheDir string

	// Prompt is called once, as soon as the device code is available. A login
	// that computes the prompt but does not display it until the flow finishes
	// is a login that appears to hang, so this is a callback rather than a
	// return value.
	Prompt func(Prompt)

	// Sleep is the delay between polls. Tests replace it; nil means time.Sleep.
	Sleep func(time.Duration)
	// Now is the clock. Tests replace it; nil means time.Now.
	Now func() time.Time
}

// Result reports what a login produced. Deliberately no token field: the token
// goes to the cache and nowhere else, so it cannot be logged by a caller that
// prints its result struct.
type Result struct {
	// CachePath is the file written.
	CachePath string
	// ExpiresAt is when the token stops working.
	ExpiresAt time.Time
	// Polls is how many CreateToken calls it took.
	Polls int
}

// cachedToken is the SDK's SSO token cache format. Field names and the RFC3339
// expiry are the interoperability contract with the AWS CLI and the SDKs; this
// struct exists to match them, not to be automat's own design.
type cachedToken struct {
	StartURL              string `json:"startUrl"`
	Region                string `json:"region"`
	AccessToken           string `json:"accessToken"`
	ExpiresAt             string `json:"expiresAt"`
	ClientID              string `json:"clientId,omitempty"`
	ClientSecret          string `json:"clientSecret,omitempty"`
	RegistrationExpiresAt string `json:"registrationExpiresAt,omitempty"`
	RefreshToken          string `json:"refreshToken,omitempty"`
}

// Login runs the device authorization grant and writes the token cache.
//
// The sequence is RFC 8628: register a client, start the authorization and show
// the operator a code, then poll until they approve. Everything interesting is in
// how the polling handles each error the token endpoint can return — see poll.
func Login(ctx context.Context, api awsapi.SSOOIDCAPI, opts Options) (*Result, error) {
	if err := opts.check(); err != nil {
		return nil, err
	}
	opts.applyDefaults()

	reg, err := api.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String(clientName),
		ClientType: aws.String(clientType),
		Scopes:     opts.Scopes,
	})
	if err != nil {
		return nil, fmt.Errorf("register with the identity provider at %s: %w\n"+
			"Check that the start URL is correct and that %s is the region the identity "+
			"store lives in — an SSO instance in another region rejects registration here",
			opts.StartURL, err, opts.Region)
	}
	if reg.ClientId == nil || reg.ClientSecret == nil {
		return nil, errors.New("the identity provider registered a client without returning " +
			"credentials for it; this is a provider fault, not a configuration problem")
	}

	auth, err := api.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(opts.StartURL),
	})
	if err != nil {
		return nil, fmt.Errorf("start device authorization at %s: %w", opts.StartURL, err)
	}
	if auth.DeviceCode == nil {
		return nil, errors.New("the identity provider started an authorization without returning " +
			"a device code; this is a provider fault, not a configuration problem")
	}

	opts.Prompt(Prompt{
		VerificationURI:         aws.ToString(auth.VerificationUri),
		VerificationURIComplete: aws.ToString(auth.VerificationUriComplete),
		UserCode:                aws.ToString(auth.UserCode),
		ExpiresIn:               time.Duration(auth.ExpiresIn) * time.Second,
	})

	tok, polls, err := poll(ctx, api, reg, auth, opts)
	if err != nil {
		return nil, err
	}

	expiresAt := opts.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	path, err := writeCache(opts, cachedToken{
		StartURL:     opts.StartURL,
		Region:       opts.Region,
		AccessToken:  aws.ToString(tok.AccessToken),
		ExpiresAt:    expiresAt.UTC().Format(time.RFC3339),
		ClientID:     aws.ToString(reg.ClientId),
		ClientSecret: aws.ToString(reg.ClientSecret),
		RefreshToken: aws.ToString(tok.RefreshToken),
	})
	if err != nil {
		return nil, err
	}
	return &Result{CachePath: path, ExpiresAt: expiresAt, Polls: polls}, nil
}

// poll waits for the operator to approve, and is where the device flow is either
// usable or not.
//
// The token endpoint's errors are not interchangeable, and treating them as one
// class is the classic bug in a device-flow implementation:
//
//   - AuthorizationPending is the normal case for every poll before the operator
//     finishes clicking. Treating it as a failure makes login never work.
//   - SlowDown means back off. Ignoring it gets the client throttled, which
//     presents as a login that fails for no visible reason.
//   - ExpiredToken means the code timed out. It needs a distinct message, because
//     the fix is "run it again", not "check your configuration".
//   - AccessDenied means the operator (or their administrator) refused. Retrying
//     is wrong and the message must not suggest it.
//
// Anything else is returned as-is; inventing a remediation for an error nobody
// anticipated is how a tool sends someone down the wrong path.
func poll(ctx context.Context, api awsapi.SSOOIDCAPI, reg *ssooidc.RegisterClientOutput,
	auth *ssooidc.StartDeviceAuthorizationOutput, opts Options) (*ssooidc.CreateTokenOutput, int, error) {
	interval := time.Duration(auth.Interval) * time.Second
	switch {
	case interval <= 0:
		interval = defaultPollInterval
	case interval < minPollInterval:
		interval = minPollInterval
	case interval > maxPollInterval:
		interval = maxPollInterval
	}

	deadline := opts.Now().Add(maxFlowDuration)
	if auth.ExpiresIn > 0 {
		if d := opts.Now().Add(time.Duration(auth.ExpiresIn) * time.Second); d.Before(deadline) {
			deadline = d
		}
	}

	in := &ssooidc.CreateTokenInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		DeviceCode:   auth.DeviceCode,
		GrantType:    aws.String(grantType),
	}

	for polls := 1; ; polls++ {
		// Context first: a cancelled login should stop, not poll once more.
		if err := ctx.Err(); err != nil {
			return nil, polls - 1, fmt.Errorf("login cancelled after %d %s: %w",
				polls-1, plural("poll", polls-1), err)
		}
		tok, err := api.CreateToken(ctx, in)
		if err == nil {
			if tok.AccessToken == nil || aws.ToString(tok.AccessToken) == "" {
				return nil, polls, errors.New("the identity provider approved the login but " +
					"returned no access token; this is a provider fault")
			}
			return tok, polls, nil
		}

		switch errorCode(err) {
		case "AuthorizationPendingException", "authorization_pending":
			// The expected case. Fall through to the sleep below.
		case "SlowDownException", "slow_down":
			// RFC 8628 §3.5: increase the interval. Five seconds is the
			// increment the RFC suggests.
			interval += 5 * time.Second
			if interval > maxPollInterval {
				interval = maxPollInterval
			}
		case "ExpiredTokenException", "expired_token":
			return nil, polls, fmt.Errorf("the login code expired before it was approved "+
				"(waited %s). Run `automat login` again and complete the approval in the "+
				"browser", opts.Now().Sub(deadline.Add(-maxFlowDuration)).Round(time.Second))
		case "AccessDeniedException", "access_denied":
			return nil, polls, errors.New("the login was denied. Either it was declined in the " +
				"browser, or the identity provider does not permit this client — ask whoever " +
				"administers the SSO instance whether the automat client is allowed")
		default:
			return nil, polls, fmt.Errorf("waiting for login approval: %w", err)
		}

		if !opts.Now().Add(interval).Before(deadline) {
			return nil, polls, fmt.Errorf("gave up waiting for login approval after %d %s. "+
				"The code was never confirmed in the browser; run `automat login` again",
				polls, plural("poll", polls))
		}
		opts.Sleep(interval)
	}
}

// errorCode extracts an API error code, tolerating both the modeled exception
// names and the OAuth-style codes, since the two spellings coexist in the wild.
func errorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// writeCache writes the token to the SDK's cache location.
//
// Same os.Root discipline as internal/bundle, and for a sharper reason: this file
// is a live bearer token. A symlink planted at the cache path — by anything that
// can write into ~/.aws/sso/cache, including a previous compromise — would
// otherwise cause automat to write a credential wherever the link points.
func writeCache(opts Options, tok cachedToken) (string, error) {
	dir := opts.CacheDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate the home directory for the token cache: %w", err)
		}
		dir = filepath.Join(home, ".aws", "sso", "cache")
	}
	// safeio.EnsureDir, not MkdirAll followed by OpenRoot. Those are two
	// resolutions of the same name with a window between them, and what lands here
	// is a bearer token: anything that can write into ~/.aws/sso — including a
	// previous compromise — could otherwise put a symlink at the cache directory
	// and choose where the credential is written. EnsureDir creates the final
	// component through a descriptor on its parent and inspects what is already
	// there rather than assuming it is the directory that was wanted.
	root, err := safeio.EnsureDir(dir, cacheDirMode)
	if err != nil {
		return "", fmt.Errorf("prepare the token cache directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	// Tighten the directory if it was created loose, or predates this code.
	if d, derr := root.Open("."); derr == nil {
		if fi, serr := d.Stat(); serr == nil && fi.Mode().Perm() != cacheDirMode {
			_ = d.Chmod(cacheDirMode)
		}
		_ = d.Close()
	}

	name := cacheFileName(opts.StartURL)
	path := filepath.Join(dir, name)

	// gosec G117 flags marshaling a struct whose field names look like secrets. They
	// are secrets, and serializing them is the point: this file *is* the SSO token
	// cache, and the field names are the interoperability contract with the AWS CLI
	// and every SDK's credential chain (see cachedToken). Writing anything else here
	// produces a file automat can write and nothing else can read, including
	// `aws sso logout`.
	//
	// What makes that acceptable is where the bytes go, not that they exist: mode
	// 0600 in a 0700 directory, through the checks below, and never into an error
	// message — TestNoErrorPathLeaksTheToken and TestResultDoesNotCarryTheToken hold
	// that line. The alternative gosec is hinting at, not persisting the token, means
	// not implementing the device flow.
	data, err := json.Marshal(tok) //nolint:gosec // G117: this file is the SSO token cache; see above.
	if err != nil {
		return "", fmt.Errorf("encode the token cache: %w", err)
	}

	// Lstat first, because it is the only thing that can see a symlink here.
	// Verified against go1.24: os.Root refuses a link whose target *escapes* the
	// root but *follows* one whose target is inside it, and silently ignores
	// syscall.O_NOFOLLOW in the flags it is given — and the f.Stat() below reports
	// the link's target, which is an ordinary regular file. So a link to a sibling
	// name is followed by every other check in this function. That is not an
	// escaped write but a chosen one: whoever planted it reads the token afterwards,
	// and `aws sso logout` clears the name automat wrote rather than the name the
	// token landed in.
	//
	// This is a check on a name, so it is not sufficient on its own; the descriptor
	// checks after the open are what confirm the file that got opened. The two are
	// tied together by the os.SameFile comparison below.
	existing, existed := fs.FileInfo(nil), false
	if fi, lerr := root.Lstat(name); lerr == nil {
		if fi.Mode()&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("the token cache entry %s is a symbolic link, and automat will "+
				"not write a credential through one: whoever controls the link controls where your "+
				"access token lands, and `aws sso logout` would not clear it. Remove it, or run "+
				"`aws sso logout` to clear the cache, then try again", path)
		}
		// Refused before the open, not after, because for a FIFO there is no
		// "after": opening one for writing blocks until a reader arrives, so a
		// mode-0600 pipe the operator owns hangs `automat login` indefinitely with
		// no output. Found by jam-checking this function — the descriptor check
		// below cannot be reached in that case, which is exactly why it is not the
		// only check.
		if !fi.Mode().IsRegular() {
			return "", fmt.Errorf("the token cache entry %s is not a regular file (mode %s). "+
				"automat will not write a credential through it. Remove it, or run "+
				"`aws sso logout` to clear the cache, then try again", path, fi.Mode())
		}
		existing, existed = fi, true
	}

	// Open without O_TRUNC, then check the descriptor, then truncate. Truncating
	// first would destroy the file this code is about to refuse to write.
	//
	// O_NONBLOCK covers the residual FIFO case the Lstat above cannot: a pipe
	// swapped in after the check. Without it that open never returns and the
	// process hangs holding a live token in memory. It is otherwise a no-op on a
	// regular file, which is all this open is ever meant to reach.
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|safeio.OpenNonBlock, cacheFileMode)
	if err != nil {
		// The open itself fails for a directory, and on some platforms for a device,
		// before the mode check below can report it. Ask what is there — through the
		// same root, so nothing outside this directory is consulted — so the
		// operator gets the fix rather than a raw openat error. This is a diagnostic
		// path only: it runs after the write has already failed and it grants
		// nothing, so the second resolution cannot be used to redirect anything.
		if fi, lerr := root.Lstat(name); lerr == nil && !fi.Mode().IsRegular() {
			return "", fmt.Errorf("the token cache entry %s is not a regular file (mode %s). "+
				"automat will not write a credential through it. Remove it, or run "+
				"`aws sso logout` to clear the cache, then try again", path, fi.Mode())
		}
		return "", fmt.Errorf("open the token cache %s for writing: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return "", fmt.Errorf("inspect the token cache %s: %w", path, err)
	}
	// Refuse anything that is not a regular file. A symlink is an attempt to
	// redirect a credential; a directory or a device is a jam that would otherwise
	// surface as a confusing write error.
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return "", fmt.Errorf("the token cache entry %s is not a regular file (mode %s). "+
			"automat will not write a credential through it. Remove it, or run "+
			"`aws sso logout` to clear the cache, then try again", path, st.Mode())
	}
	// Tie the name that was inspected to the descriptor that was opened. If they are
	// not the same object, something swapped the entry in between and automat is
	// about to write a credential into a file it never checked.
	if existed && !os.SameFile(existing, st) {
		_ = f.Close()
		return "", fmt.Errorf("the token cache entry %s changed while automat was opening it, so "+
			"the file it checked is not the file it opened — something else is writing that path. "+
			"No token was written; investigate before retrying", path)
	}
	// A hardlink is a regular file by every mode check and Lstat cannot tell one
	// from an ordinary file: only the link count distinguishes them. Writing through
	// one copies a bearer token into whatever else shares the inode.
	if n, ok := safeio.LinkCount(st); ok && n > 1 {
		_ = f.Close()
		return "", fmt.Errorf("the token cache entry %s has %d hard links, so writing it would "+
			"copy your access token into whatever else shares that file. Remove it, or run "+
			"`aws sso logout` to clear the cache, then try again", path, n)
	}
	// O_CREATE's mode is masked by the umask and ignored entirely for a file that
	// already exists, so set it explicitly — on the descriptor, so there is no
	// window in which the file exists with the wrong mode under a resolvable name.
	if cerr := f.Chmod(cacheFileMode); cerr != nil {
		_ = f.Close()
		return "", fmt.Errorf("restrict the token cache %s to the owner: %w", path, cerr)
	}
	// Truncate here rather than via O_TRUNC, so the checks above ran against the
	// file's real contents and an entry this code refuses is left intact. Chmod
	// precedes it so there is no moment in which a longer previous token is
	// readable at a wider mode.
	if terr := f.Truncate(0); terr != nil {
		_ = f.Close()
		return "", fmt.Errorf("truncate the token cache %s: %w", path, terr)
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		// Deliberately not wrapping the token or the data: a write error on a
		// credential file should not print the credential.
		return "", fmt.Errorf("write the token cache %s: %w", path, werr)
	}
	if cerr := f.Close(); cerr != nil {
		return "", fmt.Errorf("close the token cache %s: %w", path, cerr)
	}
	return path, nil
}

// cacheFileName is the SDK's cache key: the lowercase hex SHA-1 of the start URL.
//
// SHA-1 is not a security decision here and must not be "upgraded". It is the
// interoperability contract — the AWS CLI and the AWS SDKs compute this exact
// name, and a different hash produces a file automat writes and nothing reads,
// including `aws sso logout`. The input is a URL the operator typed, the output
// is a filename, and collision resistance is not load-bearing for either.
func cacheFileName(startURL string) string {
	sum := sha1.Sum([]byte(startURL)) //nolint:gosec // Interop, not integrity.
	return hex.EncodeToString(sum[:]) + ".json"
}

// check validates the options before any network call. The start URL is the one
// value worth being strict about: it is operator-supplied, it determines both the
// registration target and the cache filename, and a scheme other than https on a
// bearer-token exchange is not a preference.
func (o *Options) check() error {
	if strings.TrimSpace(o.StartURL) != o.StartURL || o.StartURL == "" {
		return errors.New("the SSO start URL is empty or has surrounding whitespace; set it with " +
			"--start-url or in the config file, e.g. https://example.awsapps.com/start")
	}
	u, err := url.Parse(o.StartURL)
	if err != nil {
		return fmt.Errorf("the SSO start URL is not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("the SSO start URL uses scheme %q; automat requires https, because this "+
			"flow exchanges a bearer token over it", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("the SSO start URL has no host; it should look like " +
			"https://example.awsapps.com/start")
	}
	if o.Region == "" {
		return errors.New("no SSO region set. This is the region the identity store lives in, " +
			"which is not necessarily where accounts are vended; set it with --sso-region or as " +
			"`region` in the config context")
	}
	for _, s := range o.Scopes {
		// A scope reaching the request unvalidated is a header-injection
		// surface, and a scope automat does not need is a broader token than it
		// asked for. Both are cheap to refuse.
		if s == "" || strings.ContainsAny(s, " \t\r\n\"\\") {
			return fmt.Errorf("scope %q contains whitespace or a quote; scopes are "+
				"space-delimited identifiers such as sso:account:access", s)
		}
	}
	return nil
}

func (o *Options) applyDefaults() {
	if len(o.Scopes) == 0 {
		// The narrowest scope that lets the resulting token list accounts and
		// fetch role credentials, which is all automat does with it.
		o.Scopes = []string{"sso:account:access"}
	}
	if o.Prompt == nil {
		o.Prompt = func(Prompt) {}
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// String renders the operator-facing prompt.
//
// Both forms are shown, deliberately. The complete URL is one click; the code is
// how the operator verifies the page they land on is the request they made, and
// it is the fallback when a terminal wraps the long URL into something
// unclickable.
func (p Prompt) String() string {
	var b strings.Builder
	b.WriteString("Confirm this login in a browser.\n\n")
	if p.VerificationURIComplete != "" {
		fmt.Fprintf(&b, "  Open:  %s\n", p.VerificationURIComplete)
		fmt.Fprintf(&b, "  Or go to %s and enter the code below.\n", p.VerificationURI)
	} else {
		fmt.Fprintf(&b, "  Open:  %s\n", p.VerificationURI)
	}
	fmt.Fprintf(&b, "  Code:  %s\n", p.UserCode)
	if p.ExpiresIn > 0 {
		fmt.Fprintf(&b, "\nThe code expires in %s. Waiting for approval...\n",
			p.ExpiresIn.Round(time.Second))
	}
	b.WriteString("\nCheck that the page shows the code above before approving.\n")
	return b.String()
}

// String renders the result. No token, and no expiry precision beyond the minute
// — this line ends up in terminals, scrollback, and pasted issue reports.
func (r *Result) String() string {
	return fmt.Sprintf("Logged in. Token cached in %s, valid until %s.\n"+
		"Other AWS tools on this machine will use it too; `aws sso logout` clears it.",
		r.CachePath, r.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
}

// WriteTo prints the result, for a caller that has an io.Writer and no opinion.
func (r *Result) WriteTo(w io.Writer) (int64, error) {
	n, err := fmt.Fprintln(w, r.String())
	return int64(n), err
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
