package gostdlib

import (
	"golang.org/x/crypto/scrypt"

	"github.com/safing/jess/tools"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "SCRYPT-20",
			Purpose:       tools.PurposePassDerivation,
			Options:       []uint8{tools.OptionNeedsDefaultKeySize},
			SecurityLevel: 0, // security of default key size
			Comment:       "",
			Author:        "Colin Percival, 2009",
		},
		Factory: func() tools.ToolLogic {
			return &SCRYPT{
				n: 1 << 20, // 2^20 resp. 1,048,576 - CPU/memory cost parameter
				r: 8,       // The blocksize parameter
				p: 1,       // Parallelization parameter
			}
		},
	})
}

// SCRYPT implements the cryptographic interface for SCRYPT password derivation.
type SCRYPT struct {
	tools.ToolLogicBase
	n int // CPU/memory cost parameter
	r int // The blocksize parameter
	p int // Parallelization parameter
}

// DeriveKeyFromPassword implements the ToolLogic interface.
func (sc *SCRYPT) DeriveKeyFromPassword(password []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, sc.n, sc.r, sc.p, sc.Helper().DefaultSymmetricKeySize())
}
