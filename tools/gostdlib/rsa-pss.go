package gostdlib

import (
	"crypto/rsa"
	"errors"

	"github.com/safing/jess/tools"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:    "RSA-PSS",
			Purpose: tools.PurposeSigning,
			Options: []uint8{
				tools.OptionNeedsManagedHasher,
				tools.OptionNeedsSecurityLevel,
			},
			Comment: "RFC 8017",
			Author:  "Mihir Bellare, Phillip Rogaway, 1998",
		},
		Factory: func() tools.ToolLogic { return &RsaPSS{} },
	})
}

// RsaPSS implements the cryptographic interface for RSA PSS signatures.
type RsaPSS struct {
	rsaBase
}

// Sign implements the ToolLogic interface.
func (pss *RsaPSS) Sign(data, associatedData []byte, signet tools.SignetInt) ([]byte, error) {
	rsaPrivKey, ok := signet.PrivateKey().(*rsa.PrivateKey)
	if !ok {
		return nil, tools.ErrInvalidKey
	}

	hashsum, err := pss.ManagedHashSum()
	if err != nil {
		return nil, err
	}
	if pss.HashTool().CryptoHashID == 0 {
		return nil, errors.New("tool PSS is only compatible with Golang crypto.Hash hash functions")
	}

	return rsa.SignPSS(
		pss.Helper().Random(),
		rsaPrivKey,
		pss.HashTool().CryptoHashID,
		hashsum,
		nil, // *rsa.PSSOptions
	)
}

// Verify implements the ToolLogic interface.
func (pss *RsaPSS) Verify(data, associatedData, signature []byte, signet tools.SignetInt) error {
	rsaPubKey, ok := signet.PublicKey().(*rsa.PublicKey)
	if !ok {
		return tools.ErrInvalidKey
	}

	hashsum, err := pss.ManagedHashSum()
	if err != nil {
		return err
	}
	if pss.HashTool().CryptoHashID == 0 {
		return errors.New("tool PSS is only compatible with Golang crypto.Hash hash functions")
	}

	return rsa.VerifyPSS(
		rsaPubKey,
		pss.HashTool().CryptoHashID,
		hashsum,
		signature,
		nil, // *rsa.PSSOptions
	)
}
