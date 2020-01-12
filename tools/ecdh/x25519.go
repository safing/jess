package ecdh

import (
	"crypto"

	"github.com/safing/jess/tools"
	"github.com/safing/portbase/container"

	"github.com/aead/ecdh"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "ECDH-X25519",
			Purpose:       tools.PurposeKeyExchange,
			SecurityLevel: 128,
			Comment:       "",
			Author:        "Daniel J. Bernstein, 2005",
		},
		Factory: func() tools.ToolLogic { return &X25519Curve{} },
	})
}

// X25519Curve implements the cryptographic interface for the ECDH X25519 key exchange.
type X25519Curve struct {
	tools.ToolLogicBase
}

// MakeSharedKey implements the ToolLogic interface.
func (ec *X25519Curve) MakeSharedKey(local tools.SignetInt, remote tools.SignetInt) ([]byte, error) {
	return ecdh.X25519().ComputeSecret(local.PrivateKey(), remote.PublicKey()), nil
}

// LoadKey implements the ToolLogic interface.
func (ec *X25519Curve) LoadKey(signet tools.SignetInt) error {
	var pubKey crypto.PublicKey
	var privKey crypto.PrivateKey

	key, public := signet.GetStoredKey()
	c := container.New(key)

	// check serialization version
	version, err := c.GetNextN8()
	if err != nil || version != 1 {
		return tools.ErrInvalidKey
	}

	// load public key
	data, err := c.Get(32)
	if err != nil {
		return tools.ErrInvalidKey
	}
	var pubKeyData [32]byte
	copy(pubKeyData[:], data)
	pubKey = pubKeyData

	// check public key
	err = ecdh.X25519().Check(pubKey)
	if err != nil {
		return tools.ErrInvalidKey
	}

	// load private key
	if !public {
		data, err = c.Get(32)
		if err != nil {
			return tools.ErrInvalidKey
		}
		var privKeyData [32]byte
		copy(privKeyData[:], data)
		privKey = privKeyData
	}

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// StoreKey implements the ToolLogic interface.
func (ec *X25519Curve) StoreKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()
	public := privKey == nil

	// create storage with serialization version
	c := container.New()
	c.AppendNumber(1)

	// store keys
	pubKeyData := pubKey.([32]byte)
	c.Append(pubKeyData[:])
	if !public {
		privKeyData := privKey.([32]byte)
		c.Append(privKeyData[:])
	}

	signet.SetStoredKey(c.CompileData(), public)
	return nil
}

// GenerateKey implements the ToolLogic interface.
func (ec *X25519Curve) GenerateKey(signet tools.SignetInt) error {
	// define variable types for API security
	var pubKey crypto.PublicKey
	var privKey crypto.PrivateKey
	var err error

	// generate keys
	privKey, pubKey, err = ecdh.X25519().GenerateKey(ec.Helper().Random())
	if err != nil {
		return err
	}

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// BurnKey implements the ToolLogic interface.
func (ec *X25519Curve) BurnKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()

	// burn public key
	if pubKey != nil {
		data, ok := pubKey.([32]byte)
		if ok {
			ec.Helper().Burn(data[:])
		}
	}

	// burn private key
	if privKey != nil {
		data, ok := privKey.([32]byte)
		if ok {
			ec.Helper().Burn(data[:])
		}
	}

	return nil
}
