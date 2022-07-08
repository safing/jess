package hashtools

import (
	"crypto"
	// Register SHA2 in Go's internal registry.
	_ "crypto/sha256"
	_ "crypto/sha512"

	// Register SHA3 in Go's internal registry.
	_ "golang.org/x/crypto/sha3"

	"github.com/safing/jess/lhash"
)

func init() {
	// SHA2
	sha2Base := &HashTool{
		Comment: "FIPS 180-4",
		Author:  "NSA, 2001",
	}
	Register(sha2Base.With(&HashTool{
		Name:          "SHA2-224",
		Hash:          crypto.SHA224,
		DigestSize:    crypto.SHA224.Size(),
		BlockSize:     crypto.SHA224.New().BlockSize(),
		SecurityLevel: 112,
		Author:        "NSA, 2004",
		labeledAlg:    lhash.SHA2_224,
	}))
	Register(sha2Base.With(&HashTool{
		Name:          "SHA2-256",
		Hash:          crypto.SHA256,
		DigestSize:    crypto.SHA256.Size(),
		BlockSize:     crypto.SHA256.New().BlockSize(),
		SecurityLevel: 128,
		labeledAlg:    lhash.SHA2_256,
	}))
	Register(sha2Base.With(&HashTool{
		Name:          "SHA2-384",
		Hash:          crypto.SHA384,
		DigestSize:    crypto.SHA384.Size(),
		BlockSize:     crypto.SHA384.New().BlockSize(),
		SecurityLevel: 192,
		labeledAlg:    lhash.SHA2_384,
	}))
	Register(sha2Base.With(&HashTool{
		Name:          "SHA2-512",
		Hash:          crypto.SHA512,
		DigestSize:    crypto.SHA512.Size(),
		BlockSize:     crypto.SHA512.New().BlockSize(),
		SecurityLevel: 256,
		labeledAlg:    lhash.SHA2_512,
	}))
	Register(sha2Base.With(&HashTool{
		Name:          "SHA2-512-224",
		Hash:          crypto.SHA512_224,
		DigestSize:    crypto.SHA512_224.Size(),
		BlockSize:     crypto.SHA512_224.New().BlockSize(),
		SecurityLevel: 112,
		labeledAlg:    lhash.SHA2_512_224,
	}))
	Register(sha2Base.With(&HashTool{
		Name:          "SHA2-512-256",
		Hash:          crypto.SHA512_256,
		DigestSize:    crypto.SHA512_256.Size(),
		BlockSize:     crypto.SHA512_256.New().BlockSize(),
		SecurityLevel: 128,
		labeledAlg:    lhash.SHA2_512_256,
	}))

	// SHA3
	sha3Base := &HashTool{
		Comment: "aka Keccak, FIPS-202, optimized for hardware",
		Author:  "Guido Bertoni et al., 2015",
	}
	Register(sha3Base.With(&HashTool{
		Name:          "SHA3-224",
		Hash:          crypto.SHA3_224,
		DigestSize:    crypto.SHA3_224.Size(),
		BlockSize:     crypto.SHA3_224.New().BlockSize(),
		SecurityLevel: 112,
		labeledAlg:    lhash.SHA3_224,
	}))
	Register(sha3Base.With(&HashTool{
		Name:          "SHA3-256",
		Hash:          crypto.SHA3_256,
		DigestSize:    crypto.SHA3_256.Size(),
		BlockSize:     crypto.SHA3_256.New().BlockSize(),
		SecurityLevel: 128,
		labeledAlg:    lhash.SHA3_256,
	}))
	Register(sha3Base.With(&HashTool{
		Name:          "SHA3-384",
		Hash:          crypto.SHA3_384,
		DigestSize:    crypto.SHA3_384.Size(),
		BlockSize:     crypto.SHA3_384.New().BlockSize(),
		SecurityLevel: 192,
		labeledAlg:    lhash.SHA3_384,
	}))
	Register(sha3Base.With(&HashTool{
		Name:          "SHA3-512",
		Hash:          crypto.SHA3_512,
		DigestSize:    crypto.SHA3_512.Size(),
		BlockSize:     crypto.SHA3_512.New().BlockSize(),
		SecurityLevel: 256,
		labeledAlg:    lhash.SHA3_512,
	}))
}
