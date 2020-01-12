package lhash

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

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

	return &LabeledHash{
		alg:    alg,
		digest: digest,
	}, nil
}

// LoadFromString loads a labeled hash from the given string.
func LoadFromString(labeledHash string) (*LabeledHash, error) {
	raw, err := base64.RawURLEncoding.DecodeString(labeledHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %s", err)
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

// String returns the string representation of the labeled hash (base64 raw url encoding).
func (lh *LabeledHash) String() string {
	return base64.RawURLEncoding.EncodeToString(lh.Bytes())
}

// Matches returns true if the digest of the given data matches the hash.
func (lh *LabeledHash) Matches(data []byte) bool {
	hasher := lh.alg.new()
	_, _ = hasher.Write(data) // never returns an error
	defer hasher.Reset()      // internal state may leak data if kept in memory

	return subtle.ConstantTimeCompare(lh.digest, hasher.Sum(nil)) == 1
}
