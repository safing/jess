package lhash

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/safing/portbase/container"
)

// LabeledHash represents a typed hash value.
type LabeledHash struct {
	alg    Algorithm
	digest []byte
}

// Digest creates a new labeled hash and digests the given data.
func Digest(alg Algorithm, data []byte) *LabeledHash {
	hasher := alg.new()
	_, _ = hasher.Write(data) // never returns an error
	defer hasher.Reset()      // internal state may leak data if kept in memory

	return &LabeledHash{
		alg:    alg,
		digest: hasher.Sum(nil),
	}
}

// Load loads a labeled hash from the given []byte slice.
func Load(labeledHash []byte) (*LabeledHash, error) {
	c := container.New(labeledHash)

	algID, err := c.GetNextN64()
	if err != nil {
		return nil, fmt.Errorf("failed to parse algorithm ID: %s", err)
	}

	digest, err := c.GetNextBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to parse digest: %s", err)
	}

	if c.Length() > 0 {
		return nil, errors.New("integrity error: data left over after parsing")
	}

	alg := Algorithm(uint(algID))
	if alg.new() == nil {
		return nil, errors.New("compatibility error: invalid or unsupported algorithm")
	}

	if alg.new().Size() != len(digest) {
		return nil, errors.New("integrity error: invalid digest length")
	}

	return &LabeledHash{
		alg:    alg,
		digest: digest,
	}, nil
}

// FromHex loads a labeled hash from the given hexadecimal string.
func FromHex(hexEncoded string) (*LabeledHash, error) {
	raw, err := hex.DecodeString(hexEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %s", err)
	}

	return Load(raw)
}

// FromBase64 loads a labeled hash from the given Base64 string using raw url
// encoding.
func FromBase64(base64Encoded string) (*LabeledHash, error) {
	raw, err := base64.RawURLEncoding.DecodeString(base64Encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %s", err)
	}

	return Load(raw)
}

// FromBase58 loads a labeled hash from the given Base58 string using the BTC
// alphabet.
func FromBase58(base58Encoded string) (*LabeledHash, error) {
	raw, err := base58.Decode(base58Encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base58: %s", err)
	}

	return Load(raw)
}

// Bytes return the []byte representation of the labeled hash.
func (lh *LabeledHash) Bytes() []byte {
	c := container.New()
	c.AppendNumber(uint64(lh.alg))
	c.AppendAsBlock(lh.digest)
	return c.CompileData()
}

// Hex returns the hexadecimal string representation of the labeled hash.
func (lh *LabeledHash) Hex() string {
	return hex.EncodeToString(lh.Bytes())
}

// Base64 returns the Base64 string representation of the labeled hash using
// raw url encoding.
func (lh *LabeledHash) Base64() string {
	return base64.RawURLEncoding.EncodeToString(lh.Bytes())
}

// Base58 returns the Base58 string representation of the labeled hash using
// the BTC alphabet.
func (lh *LabeledHash) Base58() string {
	return base58.Encode(lh.Bytes())
}

// Equal returns true if the given labeled hash is equal.
// Equality is checked by comparing both the algorithm and the digest value.
func (lh *LabeledHash) Equal(other *LabeledHash) bool {
	return lh.alg == other.alg &&
		subtle.ConstantTimeCompare(lh.digest, other.digest) == 1
}

// MatchesString returns true if the digest of the given string matches the hash.
func (lh *LabeledHash) MatchesString(s string) bool {
	return lh.MatchesData([]byte(s))
}

// MatchesData returns true if the digest of the given data matches the hash.
func (lh *LabeledHash) MatchesData(data []byte) bool {
	hasher := lh.alg.new()
	_, _ = hasher.Write(data) // never returns an error
	defer hasher.Reset()      // internal state may leak data if kept in memory

	return subtle.ConstantTimeCompare(lh.digest, hasher.Sum(nil)) == 1
}
