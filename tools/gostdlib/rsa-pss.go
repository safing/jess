package gostdlib

import (
	"crypto/rsa"

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

	return rsa.SignPSS(
		pss.Helper().Random(),
		rsaPrivKey,
		pss.HashTool().Hash,
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

	return rsa.VerifyPSS(
		rsaPubKey,
		pss.HashTool().Hash,
		hashsum,
		signature,
		nil, // *rsa.PSSOptions
	)
}
