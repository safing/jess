package gostdlib

import (
	"errors"

	"github.com/safing/jess/tools"
	"golang.org/x/crypto/poly1305"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "POLY1305",
			Purpose:       tools.PurposeMAC,
			Options:       []uint8{tools.OptionHasState},
			KeySize:       32,
			SecurityLevel: 128, // TODO: do some more research
			Comment:       "RFC 7539",
			Author:        "Daniel J. Bernstein, 2005",
		},
		Factory: func() tools.ToolLogic { return &Poly1305{} },
	})
}

// Poly1305 implements the cryptographic interface for Poly1305 message authentication codes.
type Poly1305 struct {
	tools.ToolLogicBase
	key        [32]byte
	keyIsSetUp bool
	keyUsed    bool
}

// Setup implements the ToolLogic interface.
func (poly *Poly1305) Setup() (err error) {
	// get key
	err = poly.Helper().FillNewSessionKey(poly.key[:])
	if err != nil {
		return err
	}
	poly.keyIsSetUp = true

	return nil
}

// Reset implements the ToolLogic interface.
func (poly *Poly1305) Reset() error {
	// clean up key
	poly.Helper().Burn(poly.key[:])
	poly.keyUsed = false
	poly.keyIsSetUp = false

	return nil
}

// MAC implements the ToolLogic interface.
func (poly *Poly1305) MAC(data, associatedData []byte) ([]byte, error) {
	// check for key initialization
	if !poly.keyIsSetUp {
		return nil, errors.New("key not initialized")
	}
	// check for key reuse
	if poly.keyUsed {
		return nil, errors.New("key reuse detected")
	}

	// create MAC
	mac := poly1305.New(&poly.key)
	poly.keyUsed = true
	// write data
	n, err := mac.Write(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, errors.New("failed to fully write data to Poly1305 MAC")
	}
	// write associated data
	if len(associatedData) > 0 {
		n, err := mac.Write(associatedData)
		if err != nil {
			return nil, err
		}
		if n != len(associatedData) {
			return nil, errors.New("failed to fully write associated data to Poly1305 MAC")
		}
	}

	// return sum
	return mac.Sum(nil), nil
}
