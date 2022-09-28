package lhash

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

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
	_, _ = hasher.Write(data) // Never returns an error.
	defer hasher.Reset()      // Internal state may leak data if kept in memory.

	return &LabeledHash{
		alg:    alg,
		digest: hasher.Sum(nil),
	}
}

// DigestFile creates a new labeled hash and digests the given file.
func DigestFile(alg Algorithm, pathToFile string) (*LabeledHash, error) {
	// Open file that should be hashed.
	file, err := os.OpenFile(pathToFile, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return DigestFromReader(alg, file)
}

// DigestFromReader creates a new labeled hash and digests from the given reader.
func DigestFromReader(alg Algorithm, reader io.Reader) (*LabeledHash, error) {
	hasher := alg.new()
	defer hasher.Reset() // Internal state may leak data if kept in memory.

	// Pipe all data directly to the hashing algorithm.
	_, err := bufio.NewReader(reader).WriteTo(hasher)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	return &LabeledHash{
		alg:    alg,
		digest: hasher.Sum(nil),
	}, nil
}

// Load loads a labeled hash from the given []byte slice.
func Load(labeledHash []byte) (*LabeledHash, error) {
	c := container.New(labeledHash)

	algID, err := c.GetNextN64()
	if err != nil {
		return nil, fmt.Errorf("failed to parse algorithm ID: %w", err)
	}

	digest, err := c.GetNextBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to parse digest: %w", err)
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
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	return Load(raw)
}

// FromBase64 loads a labeled hash from the given Base64 string using raw url
// encoding.
func FromBase64(base64Encoded string) (*LabeledHash, error) {
	raw, err := base64.RawURLEncoding.DecodeString(base64Encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	return Load(raw)
}

// FromBase58 loads a labeled hash from the given Base58 string using the BTC
// alphabet.
func FromBase58(base58Encoded string) (*LabeledHash, error) {
	raw, err := base58.Decode(base58Encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base58: %w", err)
	}

	return Load(raw)
}

// Algorithm returns the algorithm of the labeled hash.
func (lh *LabeledHash) Algorithm() Algorithm {
	return lh.alg
}

// Sum returns the raw calculated hash digest.
func (lh *LabeledHash) Sum() []byte {
	return lh.digest
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

// EqualRaw returns true if the given raw hash digest is equal.
// Equality is checked by comparing both the digest value only.
// The caller must make sure the same algorithm is used.
func (lh *LabeledHash) EqualRaw(otherDigest []byte) bool {
	return subtle.ConstantTimeCompare(lh.digest, otherDigest) == 1
}

// Matches returns true if the digest of the given data matches the hash.
func (lh *LabeledHash) Matches(data []byte) bool {
	return lh.Equal(Digest(lh.alg, data))
}

// MatchesData returns true if the digest of the given data matches the hash.
// DEPRECATED: Use Matches instead.
func (lh *LabeledHash) MatchesData(data []byte) bool {
	return lh.Equal(Digest(lh.alg, data))
}

// MatchesString returns true if the digest of the given string matches the hash.
func (lh *LabeledHash) MatchesString(s string) bool {
	return lh.Matches([]byte(s))
}

// MatchesFile returns true if the digest of the given file matches the hash.
func (lh *LabeledHash) MatchesFile(pathToFile string) (bool, error) {
	fileHash, err := DigestFile(lh.alg, pathToFile)
	if err != nil {
		return false, err
	}

	return lh.Equal(fileHash), nil
}

// MatchesReader returns true if the digest of the given reader matches the hash.
func (lh *LabeledHash) MatchesReader(reader io.Reader) (bool, error) {
	readerHash, err := DigestFromReader(lh.alg, reader)
	if err != nil {
		return false, err
	}

	return lh.Equal(readerHash), nil
}
