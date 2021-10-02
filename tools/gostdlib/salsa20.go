package gostdlib

import (
	"golang.org/x/crypto/salsa20"

	"github.com/safing/jess/tools"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "SALSA20",
			Purpose:       tools.PurposeCipher,
			Options:       []uint8{tools.OptionHasState},
			KeySize:       32, // 265 bits
			NonceSize:     8,  // 64 bits
			SecurityLevel: 256,
			Comment:       "",
			Author:        "Daniel J. Bernstein, 2007",
		},
		Factory: func() tools.ToolLogic { return &Salsa20{} },
	})
}

// Salsa20 implements the cryptographic interface for Salsa20 encryption.
type Salsa20 struct {
	tools.ToolLogicBase
	key   [32]byte
	nonce []byte
}

// Setup implements the ToolLogic interface.
func (salsa *Salsa20) Setup() (err error) {
	// get key
	err = salsa.Helper().FillNewSessionKey(salsa.key[:])
	if err != nil {
		return err
	}

	// get nonce
	salsa.nonce, err = salsa.Helper().NewSessionNonce()
	if err != nil {
		return err
	}

	return nil
}

// Reset implements the ToolLogic interface.
func (salsa *Salsa20) Reset() error {
	// clean up keys
	salsa.Helper().Burn(salsa.key[:])
	salsa.Helper().Burn(salsa.nonce)

	return nil
}

// Encrypt implements the ToolLogic interface.
func (salsa *Salsa20) Encrypt(data []byte) ([]byte, error) {
	// encrypt
	salsa20.XORKeyStream(data, data, salsa.nonce, &salsa.key)

	return data, nil
}

// Decrypt implements the ToolLogic interface.
func (salsa *Salsa20) Decrypt(data []byte) ([]byte, error) {
	// decrypt
	salsa20.XORKeyStream(data, data, salsa.nonce, &salsa.key)

	return data, nil
}
