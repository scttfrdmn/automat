// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/scttfrdmn/automat/internal/safeio"
)

// Signer produces a detached signature over a record's hash.
//
// An interface because DESIGN §11 asks for a local key now and KMS later as a
// drop-in. The shape is chosen for what KMS can actually do: KMS signs a message
// it is handed and returns bytes, and it cannot be asked to reveal a key — so
// nothing here exposes key material, and Sign returns the wire block rather than
// raw bytes so a KMS signer can report the key ARN it actually used rather than
// one the caller assumed.
//
// The message passed to Sign is the record's record_sha256 as ASCII hex, not the
// raw digest bytes. Deliberate: the wire form is what a reader has, and a
// verifier reconstructing the message from the manifest should not have to guess
// an encoding. Ed25519 hashes internally anyway, so signing hex costs nothing.
type Signer interface {
	Sign(message []byte) (*Signature, error)
}

// Verifier checks a detached signature over a record's hash.
//
// Separate from Signer because the two live in different places: a verifying
// operator has a public key and no authority to sign, and an interface bundling
// both would make `verify` ask for a signing grant it must not have.
type Verifier interface {
	Verify(message []byte, sig *Signature) error
}

// LocalSigner signs with an in-process ed25519 key.
//
// The starting implementation DESIGN §11 asks for. A local key is a real
// improvement over nothing — it stops an editor who can write the file but not
// read the key from producing a chain that verifies — and it is not a substitute
// for KMS: whoever can read the key file can rewrite the whole chain, so what this
// buys is that the two capabilities are separable.
type LocalSigner struct {
	// KeyID names the key in the record so a verifier knows what to reach for.
	// Not the key itself and not a hash of it — an operator-chosen label.
	KeyID string
	priv  ed25519.PrivateKey
}

// NewLocalSigner returns a signer over the given private key.
func NewLocalSigner(keyID string, priv ed25519.PrivateKey) (*LocalSigner, error) {
	if keyID == "" {
		return nil, errors.New("a signing key needs an id: a signature nobody can locate a key for " +
			"is unverifiable in a way that looks verifiable, so key_id is not optional")
	}
	if !reProse.MatchString(keyID) {
		return nil, fmt.Errorf("signing key id %s contains a control character: it is written into "+
			"every record and printed back in reports", safe(keyID))
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key is %d bytes; want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &LocalSigner{KeyID: keyID, priv: priv}, nil
}

// LoadLocalSigner reads an ed25519 private key from a file and returns a signer.
//
// The key goes through safeio.ReadSecret, which is the point of routing it here
// rather than through os.ReadFile: this is a signing key, so the file must be
// owner-only, must not be a symlink someone else planted, must not be a FIFO that
// blocks, and must be the same inode that was inspected. A signing key read
// through a substituted path is an attacker signing automat's evidence.
//
// The file holds the raw 64-byte seed-and-public-key form ed25519.NewKeyFromSeed
// produces, hex-encoded with an optional trailing newline. No PEM and no
// passphrase: a format with options is a format with a weak option, and the local
// key is explicitly the stopgap until KMS.
func LoadLocalSigner(keyID, path string) (*LocalSigner, error) {
	// 2*64 hex digits plus a newline, with slack for a trailing CR. Bounded
	// because an unbounded read of an operator-supplied path is a way to exhaust
	// memory, and a signing key is a fixed size.
	const limit = 2*ed25519.PrivateKeySize + 2
	data, err := safeio.ReadSecret(path, limit)
	if err != nil {
		return nil, fmt.Errorf("read the evidence signing key: %w", err)
	}
	priv, err := decodeKey(data)
	if err != nil {
		// The error deliberately does not echo any part of the file: the whole
		// point of the file is that its value does not appear in terminals or CI
		// logs, and a "malformed key: <first bytes>" message is a key leak on the
		// unhappy path.
		return nil, fmt.Errorf("the evidence signing key in %s is not a hex-encoded ed25519 private "+
			"key (%w) — generate one with `automat` and keep it 0600, or point at the right file", path, err)
	}
	return NewLocalSigner(keyID, priv)
}

func decodeKey(data []byte) (ed25519.PrivateKey, error) {
	trimmed := trimSpaceBytes(data)
	buf := make([]byte, ed25519.PrivateKeySize)
	n, err := hexDecode(buf, trimmed)
	if err != nil {
		return nil, err
	}
	if n != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decoded to %d bytes; want %d", n, ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(buf), nil
}

// Sign implements Signer.
func (s *LocalSigner) Sign(message []byte) (*Signature, error) {
	if len(s.priv) != ed25519.PrivateKeySize {
		return nil, errors.New("this signer holds no key; build it with NewLocalSigner or LoadLocalSigner")
	}
	sig := ed25519.Sign(s.priv, message)
	return &Signature{
		Algorithm: string(AlgEd25519),
		KeyID:     s.KeyID,
		Value:     base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verifier returns a verifier over this signer's public key, for the round trip a
// test and a same-process verify both want.
func (s *LocalSigner) Verifier() *LocalVerifier {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return &LocalVerifier{KeyID: s.KeyID, Pub: pub}
}

// LocalVerifier checks ed25519 signatures against a public key.
type LocalVerifier struct {
	// KeyID is the key this verifier holds. A record naming a different key is
	// refused rather than checked against this one — see Verify.
	KeyID string
	Pub   ed25519.PublicKey
}

// Verify implements Verifier.
func (v *LocalVerifier) Verify(message []byte, sig *Signature) error {
	if sig == nil {
		return errors.New("no signature to verify")
	}
	if sig.Algorithm != string(AlgEd25519) {
		return fmt.Errorf("record is signed with %s and this verifier holds an ed25519 key; "+
			"supply the matching verifier rather than treating the mismatch as a bad signature",
			safe(sig.Algorithm))
	}
	if v.KeyID != "" && sig.KeyID != v.KeyID {
		// Refused rather than attempted. Checking a record against a key it does
		// not name would report "signature invalid" for a manifest that is
		// perfectly sound and signed by a key the operator simply did not supply —
		// which is the reading that gets a real chain declared broken.
		return fmt.Errorf("record is signed by key %s and this verifier holds key %s; "+
			"supply the key the record names", safe(sig.KeyID), safe(v.KeyID))
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("signature value is not base64: %w", err)
	}
	if len(v.Pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verifier holds a %d-byte public key; want %d", len(v.Pub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(v.Pub, message, raw) {
		return errors.New("the signature does not match this record's hash under the named key")
	}
	return nil
}

// trimSpaceBytes drops leading and trailing ASCII whitespace. Hand-rolled rather
// than bytes.TrimSpace only to keep the key bytes out of any function that might
// grow a log line later; the behaviour is the same for the ASCII input this
// accepts.
func trimSpaceBytes(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func hexDecode(dst, src []byte) (int, error) {
	if len(src)%2 != 0 {
		return 0, fmt.Errorf("odd number of hex digits (%d)", len(src))
	}
	if len(src)/2 > len(dst) {
		return 0, fmt.Errorf("%d hex digits decode to %d bytes; want at most %d",
			len(src), len(src)/2, len(dst))
	}
	for i := 0; i < len(src)/2; i++ {
		hi, err := hexVal(src[2*i])
		if err != nil {
			return 0, err
		}
		lo, err := hexVal(src[2*i+1])
		if err != nil {
			return 0, err
		}
		dst[i] = hi<<4 | lo
	}
	return len(src) / 2, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	// Does not name the byte: it is one byte of a signing key.
	return 0, errors.New("contains a character that is not a hex digit")
}

var (
	_ Signer   = (*LocalSigner)(nil)
	_ Verifier = (*LocalVerifier)(nil)
)
