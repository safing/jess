package gostdlib

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/safing/jess/tools"
)

//nolint:dupl
func init() {
	aesCtrInfo := &tools.ToolInfo{
		Purpose:   tools.PurposeCipher,
		Options:   []uint8{tools.OptionHasState},
		NonceSize: aes.BlockSize,
		Comment:   "aka Rijndael, FIPS 197",
		Author:    "Vincent Rijmen and Joan Daemen, 1998",
	}
	aesCtrFactory := func() tools.ToolLogic { return &AesCTR{} }

	tools.Register(&tools.Tool{
		Info: aesCtrInfo.With(&tools.ToolInfo{
			Name:          "AES128-CTR",
			KeySize:       16, // 128 bits
			SecurityLevel: 128,
		}),
		Factory: aesCtrFactory,
	})
	tools.Register(&tools.Tool{
		Info: aesCtrInfo.With(&tools.ToolInfo{
			Name:          "AES192-CTR",
			KeySize:       24, // 192 bits
			SecurityLevel: 192,
		}),
		Factory: aesCtrFactory,
	})
	tools.Register(&tools.Tool{
		Info: aesCtrInfo.With(&tools.ToolInfo{
			Name:          "AES256-CTR",
			KeySize:       32, // 256 bits
			SecurityLevel: 256,
		}),
		Factory: aesCtrFactory,
	})
}

// AesCTR implements the cryptographic interface for AES-CTR encryption.
type AesCTR struct {
	tools.ToolLogicBase
	stream  cipher.Stream
	key, iv []byte
}

// Setup implements the ToolLogic interface.
func (aesctr *AesCTR) Setup() (err error) {
	// get key
	aesctr.key, err = aesctr.Helper().NewSessionKey()
	if err != nil {
		return err
	}

	// get IV
	aesctr.iv, err = aesctr.Helper().NewSessionNonce()
	if err != nil {
		return err
	}

	// get cipher.Block
	block, err := aes.NewCipher(aesctr.key)
	if err != nil {
		return err
	}

	// get cipher.Stream
	aesctr.stream = cipher.NewCTR(block, aesctr.iv)

	return nil
}

// Reset implements the ToolLogic interface.
func (aesctr *AesCTR) Reset() error {
	// clean up keys
	aesctr.Helper().Burn(aesctr.key)
	aesctr.Helper().Burn(aesctr.iv)

	return nil
}

// Encrypt implements the ToolLogic interface.
func (aesctr *AesCTR) Encrypt(data []byte) ([]byte, error) {
	// encrypt
	aesctr.stream.XORKeyStream(data, data)

	return data, nil
}

// Decrypt implements the ToolLogic interface.
func (aesctr *AesCTR) Decrypt(data []byte) ([]byte, error) {
	// decrypt
	aesctr.stream.XORKeyStream(data, data)

	return data, nil
}
