package gostdlib

import (
	"crypto/rsa"
	"fmt"

	"github.com/safing/jess/tools"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:    "RSA-OAEP",
			Purpose: tools.PurposeKeyEncapsulation,
			Options: []uint8{
				tools.OptionNeedsDedicatedHasher,
				tools.OptionNeedsSecurityLevel,
			},
			Comment: "", // TODO
			Author:  "", // TODO
		},
		Factory: func() tools.ToolLogic { return &RsaOAEP{} },
	})
}

// RsaOAEP implements the cryptographic interface for RSA OAEP encryption.
type RsaOAEP struct {
	rsaBase
}

// EncapsulateKey implements the ToolLogic interface.
func (oaep *RsaOAEP) EncapsulateKey(key []byte, signet tools.SignetInt) ([]byte, error) {
	// transform public key
	rsaPubKey, ok := signet.PublicKey().(*rsa.PublicKey)
	if !ok {
		return nil, tools.ErrInvalidKey
	}

	// check key length: The message must be no longer than the length of the public modulus minus twice the hash length, minus a further 2.
	maxMsgSize := rsaPubKey.Size() - (2 * oaep.HashTool().DigestSize) - 2
	if len(key) > maxMsgSize {
		return nil, fmt.Errorf(
			"key too long for encapsulation (rsa key would need to be at least %d bits in size to hold a key of %d bytes)",
			maxMsgSize*8,
			len(key),
		)
	}

	return rsa.EncryptOAEP(
		oaep.HashTool().New(),
		oaep.Helper().Random(),
		rsaPubKey,
		key,
		nil, // label
	)
}

// UnwrapKey implements the ToolLogic interface.
func (oaep *RsaOAEP) UnwrapKey(wrappedKey []byte, signet tools.SignetInt) ([]byte, error) {
	rsaPrivKey, ok := signet.PrivateKey().(*rsa.PrivateKey)
	if !ok {
		return nil, tools.ErrInvalidKey
	}

	return rsa.DecryptOAEP(
		oaep.HashTool().New(),
		oaep.Helper().Random(),
		rsaPrivKey,
		wrappedKey,
		nil, // label
	)
}
