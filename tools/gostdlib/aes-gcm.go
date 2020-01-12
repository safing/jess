package gostdlib

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/safing/jess/tools"
)

//nolint:dupl
func init() {
	aesGcmInfo := &tools.ToolInfo{
		Purpose:   tools.PurposeIntegratedCipher,
		Options:   []uint8{tools.OptionHasState},
		NonceSize: 12, // standard nonce size for GCM in Golang stdlib
		Comment:   "aka Rijndael, FIPS 197",
		Author:    "Vincent Rijmen and Joan Daemen, 1998",
	}
	aesGcmFactory := func() tools.ToolLogic { return &AesGCM{} }

	tools.Register(&tools.Tool{
		Info: aesGcmInfo.With(&tools.ToolInfo{
			Name:          "AES128-GCM",
			KeySize:       16, // 128 bits
			SecurityLevel: 128,
		}),
		Factory: aesGcmFactory,
	})
	tools.Register(&tools.Tool{
		Info: aesGcmInfo.With(&tools.ToolInfo{
			Name:          "AES192-GCM",
			KeySize:       24, // 192 bits
			SecurityLevel: 192,
		}),
		Factory: aesGcmFactory,
	})
	tools.Register(&tools.Tool{
		Info: aesGcmInfo.With(&tools.ToolInfo{
			Name:          "AES256-GCM",
			KeySize:       32, // 256 bits
			SecurityLevel: 256,
		}),
		Factory: aesGcmFactory,
	})
}

// AesGCM implements the cryptographic interface for AES-GCM encryption.
type AesGCM struct {
	tools.ToolLogicBase
	aead       cipher.AEAD
	key, nonce []byte
}

// Setup implements the ToolLogic interface.
func (aesgcm *AesGCM) Setup() (err error) {
	// get key
	aesgcm.key, err = aesgcm.Helper().NewSessionKey()
	if err != nil {
		return err
	}

	// get nonce
	aesgcm.nonce, err = aesgcm.Helper().NewSessionNonce()
	if err != nil {
		return err
	}

	// get cipher.Block
	block, err := aes.NewCipher(aesgcm.key)
	if err != nil {
		return err
	}

	// get aead interface
	aesgcm.aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	aesgcm.aead.NonceSize()

	return nil
}

// Reset implements the ToolLogic interface.
func (aesgcm *AesGCM) Reset() error {
	// clean up keys
	aesgcm.Helper().Burn(aesgcm.key)
	aesgcm.Helper().Burn(aesgcm.nonce)

	return nil
}

// AuthenticatedEncrypt implements the ToolLogic interface.
func (aesgcm *AesGCM) AuthenticatedEncrypt(data, associatedData []byte) ([]byte, error) {
	// encrypt and authenticate
	data = aesgcm.aead.Seal(data[:0], aesgcm.nonce, data, associatedData)

	return data, nil
}

// AuthenticatedDecrypt implements the ToolLogic interface.
func (aesgcm *AesGCM) AuthenticatedDecrypt(data, associatedData []byte) ([]byte, error) {
	// decrypt and authenticate
	var err error
	data, err = aesgcm.aead.Open(data[:0], aesgcm.nonce, data, associatedData)

	return data, err
}
