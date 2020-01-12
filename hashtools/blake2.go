package hashtools

import (
	"crypto"

	// register BLAKE2 in Go's internal registry
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
)

func init() {
	blake2bBase := &HashTool{
		Comment: "RFC 7693, successor of SHA3 finalist, optimized for 64 bit software",
		Author:  "Jean-Philippe Aumasson et al., 2013",
	}

	Register(blake2bBase.With(&HashTool{
		Name:          "BLAKE2s-256",
		Hash:          crypto.BLAKE2s_256,
		DigestSize:    crypto.BLAKE2s_256.Size(),
		BlockSize:     crypto.BLAKE2s_256.New().BlockSize(),
		SecurityLevel: 128,
		Comment:       "RFC 7693, successor of SHA3 finalist, optimized for 8-32 bit software",
	}))
	Register(blake2bBase.With(&HashTool{
		Name:          "BLAKE2b-256",
		Hash:          crypto.BLAKE2b_256,
		DigestSize:    crypto.BLAKE2b_256.Size(),
		BlockSize:     crypto.BLAKE2b_256.New().BlockSize(),
		SecurityLevel: 128,
	}))
	Register(blake2bBase.With(&HashTool{
		Name:          "BLAKE2b-384",
		Hash:          crypto.BLAKE2b_384,
		DigestSize:    crypto.BLAKE2b_384.Size(),
		BlockSize:     crypto.BLAKE2b_384.New().BlockSize(),
		SecurityLevel: 192,
	}))
	Register(blake2bBase.With(&HashTool{
		Name:          "BLAKE2b-512",
		Hash:          crypto.BLAKE2b_512,
		DigestSize:    crypto.BLAKE2b_512.Size(),
		BlockSize:     crypto.BLAKE2b_512.New().BlockSize(),
		SecurityLevel: 256,
	}))
}
