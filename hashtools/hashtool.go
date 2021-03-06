package hashtools

import (
	"crypto"
	"hash"
)

// HashTool holds generic information about a hash tool.
type HashTool struct {
	Name string
	Hash crypto.Hash

	DigestSize    int // in bytes
	BlockSize     int // in bytes
	SecurityLevel int // approx. attack complexity as 2^n

	Comment string
	Author  string
}

// New returns a new hash.Hash instance of the hash tool.
func (ht *HashTool) New() hash.Hash {
	return ht.Hash.New()
}

// With uses the original HashTool as a template for a new HashTool and returns the new HashTool.
func (ht *HashTool) With(changes *HashTool) *HashTool {
	if changes.Name == "" {
		changes.Name = ht.Name
	}
	if changes.Hash == 0 {
		changes.Hash = ht.Hash
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

	return changes
}
