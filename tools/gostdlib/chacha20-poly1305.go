package gostdlib

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/safing/jess/tools"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "CHACHA20-POLY1305",
			Purpose:       tools.PurposeIntegratedCipher,
			Options:       []uint8{tools.OptionHasState},
			KeySize:       chacha20poly1305.KeySize, // 256 bit
			NonceSize:     chacha20poly1305.NonceSize,
			SecurityLevel: 128, // ChaCha20 is actually 256. Limiting to 128 for now because of Poly1305. TODO: do some more research on Poly1305
			Comment:       "RFC 7539",
			Author:        "Daniel J. Bernstein, 2008 and 2005",
		},
		Factory: func() tools.ToolLogic { return &ChaCha20Poly1305{} },
	})
}

// ChaCha20Poly1305 implements the cryptographic interface for ChaCha20-Poly1305 encryption.
type ChaCha20Poly1305 struct {
	tools.ToolLogicBase
	aead       cipher.AEAD
	key, nonce []byte
}

// Setup implements the ToolLogic interface.
func (chapo *ChaCha20Poly1305) Setup() (err error) {
	// get key
	chapo.key, err = chapo.Helper().NewSessionKey()
	if err != nil {
		return err
	}

	// get nonce
	chapo.nonce, err = chapo.Helper().NewSessionNonce()
	if err != nil {
		return err
	}

	// get aead interface
	chapo.aead, err = chacha20poly1305.New(chapo.key)
	if err != nil {
		return err
	}

	return nil
}

// Reset implements the ToolLogic interface.
func (chapo *ChaCha20Poly1305) Reset() error {
	// clean up keys
	chapo.Helper().Burn(chapo.key)
	chapo.Helper().Burn(chapo.nonce)

	return nil
}

// AuthenticatedEncrypt implements the ToolLogic interface.
func (chapo *ChaCha20Poly1305) AuthenticatedEncrypt(data, associatedData []byte) ([]byte, error) {
	// encrypt and authenticate
	data = chapo.aead.Seal(data[:0], chapo.nonce, data, associatedData)

	return data, nil
}

// AuthenticatedDecrypt implements the ToolLogic interface.
func (chapo *ChaCha20Poly1305) AuthenticatedDecrypt(data, associatedData []byte) ([]byte, error) {
	// decrypt and authenticate
	var err error
	data, err = chapo.aead.Open(data[:0], chapo.nonce, data, associatedData)

	return data, err
}
