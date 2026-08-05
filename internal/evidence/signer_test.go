// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testKey is a fixed ed25519 key. Deterministic on purpose: a key from
// ed25519.GenerateKey would make every signature in these tests different on every
// run, and the golden manifest could then never carry one.
//
// The seed is 32 bytes of 0x2a. It is a test key in a public repository and must
// never be used for anything; the point of the local signer is precisely that
// whoever can read the key can rewrite the chain.
func testKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x2a
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testSigner(t *testing.T) *LocalSigner {
	t.Helper()
	s, err := NewLocalSigner("test-key-1", testKey())
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return s
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signer := testSigner(t)
	m := newTestManifest()
	r0 := mustAppend(t, m, vendRec(OpAccountCreate, ts0), signer)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), signer)

	if r0.Signature == nil {
		t.Fatal("Append with a signer produced an unsigned record")
	}
	if r0.Signature.Algorithm != string(AlgEd25519) || r0.Signature.KeyID != "test-key-1" {
		t.Errorf("signature block = %+v, want ed25519 under test-key-1", r0.Signature)
	}
	if err := m.VerifyChain(signer.Verifier()); err != nil {
		t.Errorf("a chain automat just signed must verify:\n%v", err)
	}

	// The signed message is the record's record_sha256 as ASCII hex, not the raw
	// digest bytes. Asserted directly rather than only through VerifyChain, because
	// the encoding is a wire-format commitment: a verifier reconstructing the
	// message from the manifest has the hex and nothing else, and should not have to
	// guess.
	raw, err := base64.StdEncoding.DecodeString(r0.Signature.Value)
	if err != nil {
		t.Fatalf("signature value is not base64: %v", err)
	}
	pub, ok := testKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key is not ed25519")
	}
	if !ed25519.Verify(pub, []byte(r0.RecordSHA), raw) {
		t.Error("the signature is not over the record_sha256 hex string")
	}
	digest, err := hex.DecodeString(r0.RecordSHA)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, digest, raw) {
		t.Error("the signature verifies over the raw digest bytes as well as the hex, which " +
			"would make the wire message ambiguous")
	}
}

// TestSigningTheSameRecordTwiceIsStable: ed25519 is deterministic, so re-signing an
// identical record produces an identical block. That is what lets the golden
// manifest carry a signature at all, and it also means two independent mirrors of
// one chain compare byte-for-byte (DESIGN §11).
func TestSigningTheSameRecordTwiceIsStable(t *testing.T) {
	a := newTestManifest()
	b := newTestManifest()
	ra := mustAppend(t, a, vendRec(OpAccountCreate, ts0), testSigner(t))
	rb := mustAppend(t, b, vendRec(OpAccountCreate, ts0), testSigner(t))

	if ra.Signature.Value != rb.Signature.Value {
		t.Errorf("the same record signed twice produced different signatures:\n%s\n%s",
			ra.Signature.Value, rb.Signature.Value)
	}
}

// TestAResignedEditIsStillCaught is the attack the signature is actually for.
//
// A hash chain alone cannot detect a record replaced wholesale — content, hash, and
// every downstream link rewritten consistently — because the result is a
// self-consistent chain. What stops it is that the tamperer would also have to
// produce signatures under the operator's key. Here the tamperer has their own key
// instead, which is the realistic case: they could write the file but not read the
// key.
func TestAResignedEditIsStillCaught(t *testing.T) {
	good := testSigner(t)
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), good)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), good)

	// The tamperer's key, under the SAME key id — so nothing but the cryptography
	// distinguishes it. A different id would be caught by the id check, which is a
	// weaker property.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x99
	}
	attacker, err := NewLocalSigner("test-key-1", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite records[1] completely: new content, new hash, new signature. Nothing
	// downstream to fix, since it was last.
	m.Records[1].Artifact.ContentSHA256 = otherHash
	h, err := ComputeRecordHash(m.Records[1])
	if err != nil {
		t.Fatal(err)
	}
	m.Records[1].RecordSHA = h
	sig, err := attacker.Sign([]byte(h))
	if err != nil {
		t.Fatal(err)
	}
	m.Records[1].Signature = sig

	// Without the key, the document is beyond reproach: every link holds and every
	// hash matches its content. This is the limit of the chain, stated as a test.
	if err := m.VerifyChain(nil); err != nil {
		t.Fatalf("a wholesale replacement is undetectable without a key, and asserting that here "+
			"is what stops the signature being mistaken for redundant:\n%v", err)
	}
	verr := m.VerifyChain(good.Verifier())
	if verr == nil {
		t.Fatal("VerifyChain accepted a record re-signed under a different key")
	}
	for _, want := range []string{"records[1].signature", "replaced wholesale"} {
		if !strings.Contains(verr.Error(), want) {
			t.Errorf("the error must name the record and the possibility; %q missing from:\n%v",
				want, verr)
		}
	}
}

// TestAKeyIDMismatchIsRefusedNotFailed is a usability property that is also a
// correctness one.
//
// Checking a record against a key it does not name would report "signature invalid"
// for a manifest that is perfectly sound and signed by a key the operator simply did
// not supply — and that is the reading that gets a real chain declared broken and
// an account torn down. The two situations must not produce the same message.
func TestAKeyIDMismatchIsRefusedNotFailed(t *testing.T) {
	signer := testSigner(t)
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), signer)

	other := signer.Verifier()
	other.KeyID = "the-operators-other-key"

	err := other.Verify([]byte(m.Records[0].RecordSHA), m.Records[0].Signature)
	if err == nil {
		t.Fatal("Verify accepted a signature under a key id it does not hold")
	}
	if !strings.Contains(err.Error(), "supply the key the record names") {
		t.Errorf("the error must send the operator after the right key, not after the chain:\n%v", err)
	}
	if strings.Contains(err.Error(), "does not match this record's hash") {
		t.Error("a key-id mismatch is reported as a bad signature; those are different problems " +
			"and only one of them means the evidence is suspect")
	}

	// An algorithm mismatch is the same shape of problem: a KMS-signed record read
	// with a local verifier is not a broken record.
	kms := *m.Records[0].Signature
	kms.Algorithm = string(AlgKMSECDSA256)
	err = signer.Verifier().Verify([]byte(m.Records[0].RecordSHA), &kms)
	if err == nil {
		t.Fatal("Verify accepted a KMS algorithm against an ed25519 key")
	}
	if !strings.Contains(err.Error(), "supply the matching verifier") {
		t.Errorf("the error must distinguish the wrong verifier from a bad signature:\n%v", err)
	}
}

// TestAVerifierWithNoKeyIDChecksAnyRecord: an empty KeyID means "the key I have,
// whatever the record calls it", which is what a caller holding exactly one key
// wants. It must still verify cryptographically — the empty id relaxes the label
// check, not the signature check.
func TestAVerifierWithNoKeyIDChecksAnyRecord(t *testing.T) {
	signer := testSigner(t)
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), signer)

	v := signer.Verifier()
	v.KeyID = ""
	if err := v.Verify([]byte(m.Records[0].RecordSHA), m.Records[0].Signature); err != nil {
		t.Errorf("a verifier with no key id must still verify a sound signature:\n%v", err)
	}
	if err := v.Verify([]byte(strings.Repeat("0", 64)), m.Records[0].Signature); err == nil {
		t.Error("a verifier with no key id accepted a signature over a different message; the " +
			"empty id relaxes the label check, never the cryptography")
	}
}

// TestAnUnsignedChainIsAValidDocument. Whether signatures are required is a policy
// decision above this package (schema/CHANGELOG.md), and a verifier must not turn
// "unsigned" into "invalid" — otherwise every manifest written before an operator
// adopted a key becomes unreadable the moment they do.
func TestAnUnsignedChainIsAValidDocument(t *testing.T) {
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	if m.Records[0].Signature != nil {
		t.Fatal("Append with a nil signer produced a signature")
	}
	if err := m.VerifyChain(testSigner(t).Verifier()); err != nil {
		t.Errorf("an unsigned chain must verify even when a verifier is offered:\n%v", err)
	}
}

// TestAMixedChainVerifiesTheSignedRecords is the shape an operator who adopts a key
// partway through produces. The early records cannot be signed retroactively without
// rewriting them, which is the operation the chain exists to make detectable, so a
// mixed chain is the correct and permanent outcome.
func TestAMixedChainVerifiesTheSignedRecords(t *testing.T) {
	signer := testSigner(t)
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), nil)
	mustAppend(t, m, vendRec(OpSCPEnsure, ts1), signer)

	if err := m.VerifyChain(signer.Verifier()); err != nil {
		t.Errorf("a chain signed from partway on must verify:\n%v", err)
	}
	// And the signed half is genuinely checked.
	m.Records[1].Signature.Value = base64.StdEncoding.EncodeToString(
		make([]byte, ed25519.SignatureSize))
	if err := m.VerifyChain(signer.Verifier()); err == nil {
		t.Error("VerifyChain accepted a zeroed signature on the signed record")
	}
}

// TestAnEditedRecordIsNotReportedAsASignatureProblem pins the ordering in
// VerifyChain. When a record's hash does not match its content, its signature is
// over a hash that does not belong to the content — so a "signature invalid" line
// would send the reader after the key rather than after the edit.
func TestAnEditedRecordIsNotReportedAsASignatureProblem(t *testing.T) {
	signer := testSigner(t)
	m := newTestManifest()
	mustAppend(t, m, vendRec(OpAccountCreate, ts0), signer)
	m.Records[0].Artifact.ContentSHA256 = otherHash

	err := m.VerifyChain(signer.Verifier())
	if err == nil {
		t.Fatal("VerifyChain accepted an edited record")
	}
	if !strings.Contains(err.Error(), "edited after it was written") {
		t.Errorf("the error must name the edit:\n%v", err)
	}
	if strings.Contains(err.Error(), ".signature") {
		t.Errorf("an edited record was also reported as a signature problem, which sends the "+
			"reader after the key instead of after the edit:\n%v", err)
	}
}

func TestNewLocalSignerRefusesAnUnusableKeyID(t *testing.T) {
	if _, err := NewLocalSigner("", testKey()); err == nil {
		t.Error("NewLocalSigner accepted an empty key id; a signature nobody can locate a key " +
			"for is unverifiable in a way that looks verifiable")
	}
	// The key id is written into every record and printed back in reports.
	if _, err := NewLocalSigner("key\nrecords[0].signature: forged", testKey()); err == nil {
		t.Error("NewLocalSigner accepted a key id containing a newline")
	}
	if _, err := NewLocalSigner("short", ed25519.PrivateKey{1, 2, 3}); err == nil {
		t.Error("NewLocalSigner accepted a key of the wrong length")
	}
	var empty LocalSigner
	if _, err := empty.Sign([]byte("x")); err == nil {
		t.Error("a zero-value LocalSigner signed something")
	}
}

// writeKeyFile writes a hex-encoded key at path with the given mode.
func writeKeyFile(t *testing.T, path string, key ed25519.PrivateKey, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode is masked by the umask, and these tests assert on the mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLocalSignerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	writeKeyFile(t, path, testKey(), 0o600)

	signer, err := LoadLocalSigner("test-key-1", path)
	if err != nil {
		t.Fatalf("LoadLocalSigner: %v", err)
	}
	sig, err := signer.Sign([]byte("message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.Verifier().Verify([]byte("message"), sig); err != nil {
		t.Errorf("a key loaded from disk must sign verifiably:\n%v", err)
	}
	// Hex without the trailing newline is the same key: an operator who wrote the
	// file with a shell redirect and one who used printf must not get different
	// behaviour.
	bare := filepath.Join(dir, "bare.key")
	if err := os.WriteFile(bare, []byte(hex.EncodeToString(testKey())), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocalSigner("test-key-1", bare); err != nil {
		t.Errorf("a key file with no trailing newline was refused:\n%v", err)
	}
}

// TestALooseKeyFileIsRefused: the signing key is the one file in automat that is
// genuinely a secret, and safeio.ReadSecret is the reason LoadLocalSigner does not
// use os.ReadFile.
func TestALooseKeyFileIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	writeKeyFile(t, path, testKey(), 0o644)

	_, err := LoadLocalSigner("test-key-1", path)
	if err == nil {
		t.Fatal("LoadLocalSigner accepted a world-readable signing key")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("the error must say how to fix it (CLAUDE.md rule 7):\n%v", err)
	}
}

// TestASymlinkedKeyFileIsRefused. A signing key read through a substituted path is
// an attacker signing automat's evidence, which is worse than no signature at all
// because it verifies.
func TestASymlinkedKeyFileIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.key")
	writeKeyFile(t, real, testKey(), 0o600)
	link := filepath.Join(dir, "signing.key")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	_, err := LoadLocalSigner("test-key-1", link)
	if err == nil {
		t.Fatal("LoadLocalSigner followed a symlink to a signing key")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("the error must name the cause:\n%v", err)
	}
}

// TestNoKeyMaterialAppearsInAnyError is the unhappy-path leak check.
//
// The whole point of the key file is that its contents do not appear in terminals
// or CI logs, and the tempting error message — "malformed key: <first bytes>" — is a
// key leak that only fires when something is already going wrong, which is when
// output is most likely to be pasted into a ticket.
func TestNoKeyMaterialAppearsInAnyError(t *testing.T) {
	dir := t.TempDir()
	secret := hex.EncodeToString(testKey())

	cases := []struct {
		name    string
		content string
	}{
		{"a truncated key", secret[:40]},
		{"a key with a non-hex digit", "zz" + secret[2:]},
		{"an odd number of digits", secret[:len(secret)-1]},
		{"an empty file", ""},
		{"a PEM file an operator might reach for", "-----BEGIN PRIVATE KEY-----\n" + secret[:32]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "k")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadLocalSigner("test-key-1", path)
			if err == nil {
				t.Fatalf("LoadLocalSigner accepted %s", tc.name)
			}
			msg := err.Error()
			// Any run of hex from the file is key material. Sixteen digits is
			// eight bytes, which is both far more than an accident and far less
			// than a useful quotation.
			for i := 0; i+16 <= len(tc.content); i++ {
				chunk := tc.content[i : i+16]
				if strings.Contains(msg, chunk) {
					t.Errorf("the error echoes %d bytes of the key file (%q...): an error on the "+
						"unhappy path is the output most likely to be pasted into a ticket\n%v",
						len(chunk), chunk[:8], err)
					break
				}
			}
			// It must still be actionable about the file itself.
			if !strings.Contains(msg, path) {
				t.Errorf("the error does not name the file, so the operator cannot act on it:\n%v", err)
			}
		})
	}
}

// TestALargeFileAtTheKeyPathIsRefusedWithoutReadingIt: the read is bounded because
// an operator-supplied path can name anything, and a signing key is a fixed size.
func TestALargeFileAtTheKeyPathIsRefusedWithoutReadingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	big := make([]byte, 1<<16)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadLocalSigner("test-key-1", path)
	if err == nil {
		t.Fatal("LoadLocalSigner accepted a 64KiB file as an ed25519 key")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("the error must say the file is too big rather than reporting a parse failure "+
			"over 64KiB of content:\n%v", err)
	}
}

// TestSignatureValidationMirrorsTheSchema covers the wire-block constraints, which
// matter because a signature is the one field a reader is most likely to take on
// trust.
func TestSignatureValidationMirrorsTheSchema(t *testing.T) {
	good := Signature{Algorithm: string(AlgEd25519), KeyID: "k1",
		Value: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}

	cases := []struct {
		name string
		mut  func(*Signature)
		want string
	}{
		{"an unknown algorithm", func(s *Signature) { s.Algorithm = "rot13" }, "not a signing algorithm"},
		{"no algorithm", func(s *Signature) { s.Algorithm = "" }, "not a signing algorithm"},
		{"no key id", func(s *Signature) { s.KeyID = "" }, "unverifiable in a way that looks verifiable"},
		{"a key id with a newline", func(s *Signature) { s.KeyID = "k1\nrecords[0]: ok" }, "key_id"},
		{"a value that is not base64", func(s *Signature) { s.Value = "not base64!" }, "not base64"},
		{"an empty value", func(s *Signature) { s.Value = "" }, "not base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := good
			tc.mut(&s)
			var p problems
			s.validate("records[0].signature", &p)
			if len(p.list) == 0 {
				t.Fatalf("the validator accepted %s", tc.name)
			}
			if !strings.Contains(p.list[0].Error(), tc.want) {
				t.Errorf("the problem must explain the rule; %q missing from:\n%v", tc.want, p.list[0])
			}
		})
	}

	// The KMS algorithms are named in the schema so adopting one is not a schema
	// version event (DESIGN §11). A record carrying one must validate even though
	// this package cannot produce or check it.
	for _, alg := range AllAlgorithms {
		s := good
		s.Algorithm = string(alg)
		var p problems
		s.validate("records[0].signature", &p)
		if len(p.list) != 0 {
			t.Errorf("a %s signature block does not validate; the algorithm set is named in the "+
				"schema precisely so adopting one later is not a schema event:\n%v", alg, p.list)
		}
	}
}
