package hashtools

import (
	"crypto"
	"hash"

	"github.com/safing/jess/lhash"
)

// HashTool holds generic information about a hash tool.
type HashTool struct {
	Name string

	NewHash      func() hash.Hash
	CryptoHashID crypto.Hash

	DigestSize    int // in bytes
	BlockSize     int // in bytes
	SecurityLevel int // approx. attack complexity as 2^n

	Comment string
	Author  string

	labeledAlg lhash.Algorithm
}

// New returns a new hash.Hash instance of the hash tool.
func (ht *HashTool) New() hash.Hash {
	return ht.NewHash()
}

// With uses the original HashTool as a template for a new HashTool and returns the new HashTool.
func (ht *HashTool) With(changes *HashTool) *HashTool {
	if changes.Name == "" {
		changes.Name = ht.Name
	}
	if changes.NewHash == nil {
		changes.NewHash = ht.NewHash
	}
	if changes.CryptoHashID == 0 {
		changes.CryptoHashID = ht.CryptoHashID
	}
	if changes.DigestSize == 0 {
		changes.DigestSize = ht.DigestSize
	}
	if changes.BlockSize == 0 {
		changes.BlockSize = ht.BlockSize
	}
	if changes.SecurityLevel == 0 {
		changes.SecurityLevel = ht.SecurityLevel
	}
	if changes.Comment == "" {
		changes.Comment = ht.Comment
	}
	if changes.Author == "" {
		changes.Author = ht.Author
	}
	if changes.labeledAlg == 0 {
		changes.labeledAlg = ht.labeledAlg
	}

	return changes
}

// LabeledHasher returns the corresponding labeled hashing algorithm.
func (ht *HashTool) LabeledHasher() lhash.Algorithm {
	return ht.labeledAlg
}
