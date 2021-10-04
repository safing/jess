package gostdlib

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/safing/jess/tools"
	"github.com/safing/portbase/container"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "HKDF",
			Purpose:       tools.PurposeKeyDerivation,
			Options:       []uint8{tools.OptionNeedsDedicatedHasher},
			SecurityLevel: 0, // depends on used hash function
			Comment:       "RFC 5869",
			Author:        "Hugo Krawczyk, 2010",
		},
		Factory: func() tools.ToolLogic { return &HKDF{} },
	})
}

// HKDF implements the cryptographic interface for HKDF key derivation.
type HKDF struct {
	tools.ToolLogicBase
	reader io.Reader
}

// InitKeyDerivation implements the ToolLogic interface.
func (keyder *HKDF) InitKeyDerivation(nonce []byte, material ...[]byte) error {
	// hkdf arguments: hash func() hash.Hash, secret, salt, info []byte
	// `secret` and `salt` are used for the initial `extract` operation
	// `info` is mixed into every `expand` operation
	if len(material) < 1 || len(material[0]) == 0 || len(nonce) == 0 {
		return errors.New("must supply at least one key and a nonce as key material")
	}

	keyder.reader = hkdf.New(
		keyder.HashTool().New,
		container.New(material...).CompileData(), // cryptographically secure master secret(s)
		nonce,                                    // non-secret salt
		nil,                                      // non-secret info
	)
	return nil
}

// DeriveKey implements the ToolLogic interface.
func (keyder *HKDF) DeriveKey(size int) ([]byte, error) {
	key := make([]byte, size)
	return key, keyder.DeriveKeyWriteTo(key)
}

// DeriveKeyWriteTo implements the ToolLogic interface.
func (keyder *HKDF) DeriveKeyWriteTo(newKey []byte) error {
	n, err := io.ReadFull(keyder.reader, newKey)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	if n != len(newKey) {
		return errors.New("failed to generate key: EOF")
	}
	return nil
}
