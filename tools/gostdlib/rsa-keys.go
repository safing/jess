package gostdlib

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/safing/jess/tools"

	"github.com/safing/portbase/container"
)

type rsaBase struct {
	tools.ToolLogicBase
}

// LoadKey implements the ToolLogic interface.
func (base *rsaBase) LoadKey(signet tools.SignetInt) error {
	var pubKey crypto.PublicKey
	var privKey *rsa.PrivateKey

	key, public := signet.GetStoredKey()
	c := container.New(key)

	// check serialization version
	version, err := c.GetNextN8()
	if err != nil || version != 1 {
		return tools.ErrInvalidKey
	}

	// load key
	if public {
		pubKey, err = x509.ParsePKCS1PublicKey(c.CompileData())
	} else {
		privKey, err = x509.ParsePKCS1PrivateKey(c.CompileData())
		if err != nil {
			return tools.ErrInvalidKey
		}
		// check and assign keys
		err = privKey.Validate()
		if err == nil {
			pubKey = privKey.Public()
		}
	}

	// check for error
	if err != nil {
		return tools.ErrInvalidKey
	}

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// StoreKey implements the ToolLogic interface.
func (base *rsaBase) StoreKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()
	public := privKey == nil

	// create storage with serialization version
	c := container.New()
	c.AppendNumber(1)

	// store keys
	if public {
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return tools.ErrInvalidKey
		}
		c.Append(x509.MarshalPKCS1PublicKey(rsaPubKey))

	} else {
		rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return tools.ErrInvalidKey
		}
		c.Append(x509.MarshalPKCS1PrivateKey(rsaPrivKey))
	}

	signet.SetStoredKey(c.CompileData(), public)
	return nil
}

// GenerateKey implements the ToolLogic interface.
func (base *rsaBase) GenerateKey(signet tools.SignetInt) error {
	// get key size
	keySize := getRSAKeySizeBySecurityLevel(base.Helper().MaxSecurityLevel())
	if keySize < 0 {
		return fmt.Errorf("invalid security level of %d for rsa key - rsa based cryptography is only available for levels 112 to 256 (recommended only up to 192)", base.Helper().MaxSecurityLevel())
	}

	// generate new private key
	privKey, err := rsa.GenerateKey(base.Helper().Random(), keySize)
	if err != nil {
		return err
	}
	// get public key
	pubKey := privKey.Public()

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// BurnKey implements the ToolLogic interface. This is currently ineffective, see known issues in the project's README.
func (base *rsaBase) BurnKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()

	// burn public key
	if pubKey != nil {
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if ok && rsaPubKey != nil {
			rsaPubKey.E = 0
			burnBigInt(rsaPubKey.N)
		}
	}

	// burn private key
	if privKey != nil {
		rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
		if ok && rsaPrivKey != nil {
			// private key
			burnBigInt(rsaPrivKey.D)
			for _, bigInt := range rsaPrivKey.Primes {
				burnBigInt(bigInt)
			}
			// precomputed values
			burnBigInt(rsaPrivKey.Precomputed.Dp)
			burnBigInt(rsaPrivKey.Precomputed.Dq)
			burnBigInt(rsaPrivKey.Precomputed.Qinv)
			for _, crtVal := range rsaPrivKey.Precomputed.CRTValues {
				burnBigInt(crtVal.Coeff)
				burnBigInt(crtVal.Exp)
				burnBigInt(crtVal.R)
			}
			// public key
			rsaPrivKey.PublicKey.E = 0
			burnBigInt(rsaPrivKey.PublicKey.N)
		}
	}

	return nil
}

var zeroBigInt = big.NewInt(0)

func burnBigInt(i *big.Int) {
	if i != nil {
		i.Set(zeroBigInt)
	}
}

// SecurityLevel implements the ToolLogic interface.
func (base *rsaBase) SecurityLevel(signet tools.SignetInt) (int, error) {
	if signet == nil {
		return 0, nil
	}

	pubkey := signet.PublicKey()
	if pubkey == nil {
		err := signet.LoadKey()
		if err != nil {
			return 0, fmt.Errorf("failed to load key to calculate security level: %s", err)
		}
		pubkey = signet.PublicKey()
	}
	rsaPubKey, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		return 0, tools.ErrInvalidKey
	}

	level := getSecurityLevelByRSAKeySize(rsaPubKey.Size() * 8)
	if level < 0 {
		return 0, fmt.Errorf("rsa key is too small (%d bits) and can be broken trivially", rsaPubKey.Size()*8)
	}
	return level, nil
}

func getRSAKeySizeBySecurityLevel(level int) (keySize int) {
	switch {
	case level <= 112:
		return 2048
	case level <= 128:
		return 3072
	case level <= 192:
		return 7680
	case level <= 256:
		return 15360
	default:
		return 256 // max level for rsa
	}
}

func getSecurityLevelByRSAKeySize(keySize int) (level int) {
	switch {
	case keySize >= 15360:
		return 256
	case keySize >= 7680:
		return 192
	case keySize >= 3072:
		return 128
	case keySize >= 2048:
		return 112
	case keySize >= 1024:
		return 80
	case keySize >= 512:
		return 56
	default:
		return -1 // error
	}
}
