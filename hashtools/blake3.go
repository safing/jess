package hashtools

import (
	"hash"

	"github.com/zeebo/blake3"

	"github.com/safing/jess/lhash"
)

func init() {
	Register(&HashTool{
		Name:          "BLAKE3",
		NewHash:       newBlake3,
		DigestSize:    newBlake3().Size(),
		BlockSize:     newBlake3().BlockSize(),
		SecurityLevel: 128,
		Comment:       "cryptographic hash function based on Bao and BLAKE2",
		Author:        "Jean-Philippe Aumasson et al., 2020",
		labeledAlg:    lhash.BLAKE3,
	})
}

func newBlake3() hash.Hash {
	return blake3.New()
}
