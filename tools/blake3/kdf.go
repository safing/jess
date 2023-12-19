package blake3

import (
	"errors"
	"fmt"
	"io"

	"github.com/zeebo/blake3"

	"github.com/safing/jess/tools"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "BLAKE3-KDF",
			Purpose:       tools.PurposeKeyDerivation,
			SecurityLevel: 128,
			Comment:       "cryptographic hash function based on Bao and BLAKE2",
			Author:        "Jean-Philippe Aumasson et al., 2020",
		},
		Factory: func() tools.ToolLogic { return &KDF{} },
	})
}

// KDF implements the cryptographic interface for BLAKE3 key derivation.
type KDF struct {
	tools.ToolLogicBase
	reader io.Reader
}

// InitKeyDerivation implements the ToolLogic interface.
func (keyder *KDF) InitKeyDerivation(nonce []byte, material ...[]byte) error {
	// Check params.
	if len(material) < 1 || len(material[0]) == 0 || len(nonce) == 0 {
		return errors.New("must supply at least one key and a nonce as key material")
	}

	// Setup KDF.
	// Use nonce as kdf context.
	h := blake3.NewDeriveKey(string(nonce))
	// Then add all the key material.
	for _, m := range material {
		_, _ = h.Write(m)
	}
	// Get key reader.
	keyder.reader = h.Digest()

	return nil
}

// DeriveKey implements the ToolLogic interface.
func (keyder *KDF) DeriveKey(size int) ([]byte, error) {
	key := make([]byte, size)
	return key, keyder.DeriveKeyWriteTo(key)
}

// DeriveKeyWriteTo implements the ToolLogic interface.
func (keyder *KDF) DeriveKeyWriteTo(newKey []byte) error {
	n, err := io.ReadFull(keyder.reader, newKey)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	if n != len(newKey) {
		return errors.New("failed to generate key: EOF")
	}
	return nil
}
