package ecdh

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/aead/ecdh"

	"github.com/safing/jess/tools"
	"github.com/safing/portbase/container"
)

var nistCurveInfo = &tools.ToolInfo{
	Purpose: tools.PurposeKeyExchange,
	Comment: "FIPS 186",
	Author:  "NIST, 2009",
}

func init() {
	tools.Register(&tools.Tool{
		Info: nistCurveInfo.With(&tools.ToolInfo{
			Name:          "ECDH-P224",
			SecurityLevel: 112,
		}),
		Factory: func() tools.ToolLogic { return &NistCurve{curve: ecdh.Generic(elliptic.P224())} },
	})
	tools.Register(&tools.Tool{
		Info: nistCurveInfo.With(&tools.ToolInfo{
			Name:          "ECDH-P256",
			SecurityLevel: 128,
		}),
		Factory: func() tools.ToolLogic { return &NistCurve{curve: ecdh.Generic(elliptic.P256())} },
	})
	tools.Register(&tools.Tool{
		Info: nistCurveInfo.With(&tools.ToolInfo{
			Name:          "ECDH-P384",
			SecurityLevel: 192,
		}),
		Factory: func() tools.ToolLogic { return &NistCurve{curve: ecdh.Generic(elliptic.P384())} },
	})
	tools.Register(&tools.Tool{
		Info: nistCurveInfo.With(&tools.ToolInfo{
			Name:          "ECDH-P521",
			SecurityLevel: 256,
		}),
		Factory: func() tools.ToolLogic { return &NistCurve{curve: ecdh.Generic(elliptic.P521())} },
	})
}

// NistCurve implements the cryptographic interface for ECDH key exchange with NIST curves.
type NistCurve struct {
	tools.ToolLogicBase
	curve ecdh.KeyExchange
}

// MakeSharedKey implements the ToolLogic interface.
func (ec *NistCurve) MakeSharedKey(local tools.SignetInt, remote tools.SignetInt) ([]byte, error) {
	return ec.curve.ComputeSecret(local.PrivateKey(), remote.PublicKey()), nil
}

// LoadKey implements the ToolLogic interface.
func (ec *NistCurve) LoadKey(signet tools.SignetInt) error {
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
	// extract public key data
	pointXData, err := c.GetNextBlock()
	if err != nil {
		return err
	}
	pointYData, err := c.GetNextBlock()
	if err != nil {
		return err
	}
	// transform public key data
	point := ecdh.Point{}
	point.X = new(big.Int).SetBytes(pointXData)
	point.Y = new(big.Int).SetBytes(pointYData)
	pubKey = point

	// check public key
	err = ec.curve.Check(pubKey)
	if err != nil {
		return tools.ErrInvalidKey
	}

	// load private key
	if !public {
		privKey = c.CompileData()
	}

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// StoreKey implements the ToolLogic interface.
func (ec *NistCurve) StoreKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()
	public := privKey == nil

	// create storage with serialization version
	c := container.New()
	c.AppendNumber(1)

	// store public key
	curvePoint, ok := pubKey.(ecdh.Point)
	if !ok {
		return fmt.Errorf("public key of invalid type %T", pubKey)
	}
	c.AppendAsBlock(curvePoint.X.Bytes())
	c.AppendAsBlock(curvePoint.Y.Bytes())

	// store private key
	if !public {
		privKeyData, ok := privKey.([]byte)
		if !ok {
			return fmt.Errorf("private key of invalid type %T", privKey)
		}
		c.Append(privKeyData)
	}

	signet.SetStoredKey(c.CompileData(), public)
	return nil
}

// GenerateKey implements the ToolLogic interface.
func (ec *NistCurve) GenerateKey(signet tools.SignetInt) error {
	// define variable types for API security
	var pubKey crypto.PublicKey
	var privKey crypto.PrivateKey
	var err error

	// generate keys
	privKey, pubKey, err = ec.curve.GenerateKey(ec.Helper().Random())
	if err != nil {
		return err
	}

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// BurnKey implements the ToolLogic interface. This is currently ineffective, see known issues in the project's README.
func (ec *NistCurve) BurnKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()

	// burn public key
	if pubKey != nil {
		point, ok := pubKey.(*ecdh.Point)
		if ok {
			point.X.Set(big.NewInt(0))
			point.Y.Set(big.NewInt(0))
		}
	}

	// burn private key
	if privKey != nil {
		data, ok := privKey.([]byte)
		if ok {
			ec.Helper().Burn(data)
		}
	}

	return nil
}
