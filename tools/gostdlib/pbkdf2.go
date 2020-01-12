package gostdlib

import (
	"crypto/sha256"
	"hash"

	"github.com/safing/jess/tools"

	"golang.org/x/crypto/pbkdf2"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "PBKDF2-SHA2-256",
			Purpose:       tools.PurposePassDerivation,
			Options:       []uint8{tools.OptionNeedsDefaultKeySize},
			SecurityLevel: 0, // Security Level of SHA2-256
			Comment:       "PKCS #5 v2.1, RFC 8018",
			Author:        "Burt Kaliski, RSA Laboratories, 2000/2017",
		},
		Factory: func() tools.ToolLogic {
			return &PBKDF2{
				hashFactory: sha256.New,
				iterations:  20000,
			}
		},
	})
}

// PBKDF2 implements the cryptographic interface for PBKDF2 password derivation.
type PBKDF2 struct {
	tools.ToolLogicBase
	hashFactory func() hash.Hash
	iterations  int
}

// DeriveKeyFromPassword implements the ToolLogic interface.
func (pd *PBKDF2) DeriveKeyFromPassword(password []byte, salt []byte) ([]byte, error) {
	return pbkdf2.Key(
		password,
		salt,
		pd.iterations,
		pd.Helper().DefaultSymmetricKeySize(),
		pd.hashFactory,
	), nil
}
