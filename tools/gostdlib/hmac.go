package gostdlib

import (
	"crypto/hmac"
	"errors"

	"github.com/safing/jess/tools"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:    "HMAC",
			Purpose: tools.PurposeMAC,
			Options: []uint8{
				tools.OptionNeedsDedicatedHasher,
				tools.OptionHasState,
			},
			SecurityLevel: 0, // depends on used hash function
			Comment:       "RFC 2104, FIPS 198",
			Author:        "Mihir Bellare et al., 1996",
		},
		Factory: func() tools.ToolLogic { return &HMAC{} },
	})
}

// HMAC implements the cryptographic interface for HMAC message authentication codes.
type HMAC struct {
	tools.ToolLogicBase
	key []byte
}

// Setup implements the ToolLogic interface.
func (hm *HMAC) Setup() (err error) {
	// get key
	hm.key, err = hm.Helper().NewSessionKey()
	if err != nil {
		return err
	}

	return nil
}

// Reset implements the ToolLogic interface.
func (hm *HMAC) Reset() error {
	// clean up key
	hm.Helper().Burn(hm.key)

	return nil
}

// MAC implements the ToolLogic interface.
func (hm *HMAC) MAC(data, associatedData []byte) ([]byte, error) {
	// create MAC
	mac := hmac.New(hm.HashTool().New, hm.key)
	// write data
	n, err := mac.Write(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, errors.New("failed to fully write data to HMAC hasher")
	}
	// write associated data
	if len(associatedData) > 0 {
		n, err := mac.Write(associatedData)
		if err != nil {
			return nil, err
		}
		if n != len(associatedData) {
			return nil, errors.New("failed to fully write associated data to HMAC hasher")
		}
	}

	// return sum
	return mac.Sum(nil), nil
}
