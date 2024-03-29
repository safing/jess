// Package lhash provides integrated labeled hashes.
//
//nolint:gci
package lhash

import (
	"crypto"
	"hash"
	"io"

	// Register SHA2 in Go's internal registry.
	_ "crypto/sha256"
	_ "crypto/sha512"

	// Register SHA3 in Go's internal registry.
	_ "golang.org/x/crypto/sha3"

	// Register BLAKE2 in Go's internal registry.
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"

	"github.com/zeebo/blake3"
)

// Algorithm is an identifier for a hash function.
type Algorithm uint

//nolint:golint,stylecheck // names are really the best this way
const (
	SHA2_224     Algorithm = 8
	SHA2_256     Algorithm = 9
	SHA2_384     Algorithm = 10
	SHA2_512     Algorithm = 11
	SHA2_512_224 Algorithm = 12
	SHA2_512_256 Algorithm = 13

	SHA3_224 Algorithm = 16
	SHA3_256 Algorithm = 17
	SHA3_384 Algorithm = 18
	SHA3_512 Algorithm = 19

	BLAKE2s_256 Algorithm = 24
	BLAKE2b_256 Algorithm = 25
	BLAKE2b_384 Algorithm = 26
	BLAKE2b_512 Algorithm = 27

	BLAKE3 Algorithm = 32
)

func (a Algorithm) new() hash.Hash {
	switch a {

	// SHA2
	case SHA2_224:
		return crypto.SHA224.New()
	case SHA2_256:
		return crypto.SHA256.New()
	case SHA2_384:
		return crypto.SHA384.New()
	case SHA2_512:
		return crypto.SHA512.New()
	case SHA2_512_224:
		return crypto.SHA512_224.New()
	case SHA2_512_256:
		return crypto.SHA512_256.New()

	// SHA3
	case SHA3_224:
		return crypto.SHA3_224.New()
	case SHA3_256:
		return crypto.SHA3_256.New()
	case SHA3_384:
		return crypto.SHA3_384.New()
	case SHA3_512:
		return crypto.SHA3_512.New()

		// BLAKE2
	case BLAKE2s_256:
		return crypto.BLAKE2s_256.New()
	case BLAKE2b_256:
		return crypto.BLAKE2b_256.New()
	case BLAKE2b_384:
		return crypto.BLAKE2b_384.New()
	case BLAKE2b_512:
		return crypto.BLAKE2b_512.New()

		// BLAKE3
	case BLAKE3:
		return blake3.New()

	default:
		return nil
	}
}

func (a Algorithm) String() string {
	switch a {

	// SHA2
	case SHA2_224:
		return "SHA2_224"
	case SHA2_256:
		return "SHA2_256"
	case SHA2_384:
		return "SHA2_384"
	case SHA2_512:
		return "SHA2_512"
	case SHA2_512_224:
		return "SHA2_512_224"
	case SHA2_512_256:
		return "SHA2_512_256"

	// SHA3
	case SHA3_224:
		return "SHA3_224"
	case SHA3_256:
		return "SHA3_256"
	case SHA3_384:
		return "SHA3_384"
	case SHA3_512:
		return "SHA3_512"

	// BLAKE2
	case BLAKE2s_256:
		return "BLAKE2s_256"
	case BLAKE2b_256:
		return "BLAKE2b_256"
	case BLAKE2b_384:
		return "BLAKE2b_384"
	case BLAKE2b_512:
		return "BLAKE2b_512"

		// BLAKE3
	case BLAKE3:
		return "BLAKE3"

	default:
		return "unknown"
	}
}

// RawHasher returns a new raw hasher of the algorithm.
func (a Algorithm) RawHasher() hash.Hash {
	return a.new()
}

// Digest creates a new labeled hash and digests the given data.
func (a Algorithm) Digest(data []byte) *LabeledHash {
	return Digest(a, data)
}

// DigestFile creates a new labeled hash and digests the given file.
func (a Algorithm) DigestFile(pathToFile string) (*LabeledHash, error) {
	return DigestFile(a, pathToFile)
}

// DigestFromReader creates a new labeled hash and digests from the given reader.
func (a Algorithm) DigestFromReader(reader io.Reader) (*LabeledHash, error) {
	return DigestFromReader(a, reader)
}
