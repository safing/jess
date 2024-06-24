package gostdlib

import (
	"crypto"
	"crypto/ed25519"
	"errors"

	"github.com/safing/jess/tools"
	"github.com/safing/structures/container"
)

func init() {
	tools.Register(&tools.Tool{
		Info: &tools.ToolInfo{
			Name:          "Ed25519",
			Purpose:       tools.PurposeSigning,
			Options:       []uint8{tools.OptionNeedsManagedHasher},
			SecurityLevel: 128,
			Comment:       "",
			Author:        "Daniel J. Bernstein, 2011",
		},
		Factory: func() tools.ToolLogic { return &Ed25519{} },
	})
}

// Ed25519 implements the cryptographic interface for Ed25519 signatures.
type Ed25519 struct {
	tools.ToolLogicBase
}

// Sign implements the ToolLogic interface.
func (ed *Ed25519) Sign(data, associatedData []byte, signet tools.SignetInt) ([]byte, error) {
	edPrivKey, ok := signet.PrivateKey().(ed25519.PrivateKey)
	if !ok {
		return nil, tools.ErrInvalidKey
	}
	if len(edPrivKey) != ed25519.PrivateKeySize {
		return nil, tools.ErrInvalidKey
	}

	hashsum, err := ed.ManagedHashSum()
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(edPrivKey, hashsum), nil
}

// Verify implements the ToolLogic interface.
func (ed *Ed25519) Verify(data, associatedData, signature []byte, signet tools.SignetInt) error {
	edPubKey, ok := signet.PublicKey().(ed25519.PublicKey)
	if !ok {
		return tools.ErrInvalidKey
	}
	if len(edPubKey) != ed25519.PublicKeySize {
		return tools.ErrInvalidKey
	}

	hashsum, err := ed.ManagedHashSum()
	if err != nil {
		return err
	}

	if !ed25519.Verify(edPubKey, hashsum, signature) {
		return errors.New("signature invalid")
	}
	return nil
}

// LoadKey implements the ToolLogic interface.
func (ed *Ed25519) LoadKey(signet tools.SignetInt) error {
	var pubKey crypto.PublicKey
	var privKey ed25519.PrivateKey

	key, public := signet.GetStoredKey()
	c := container.New(key)

	// check serialization version
	version, err := c.GetNextN8()
	if err != nil || version != 1 {
		return tools.ErrInvalidKey
	}

	// load public key
	data := c.CompileData()

	// assign and check data
	if public {
		if len(data) != ed25519.PublicKeySize {
			return tools.ErrInvalidKey
		}
		pubKey = ed25519.PublicKey(data)
	} else {
		if len(data) != ed25519.PrivateKeySize {
			return tools.ErrInvalidKey
		}
		privKey = ed25519.PrivateKey(data)
		pubKey = privKey.Public()
	}

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// StoreKey implements the ToolLogic interface.
func (ed *Ed25519) StoreKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()
	public := privKey == nil

	// create storage with serialization version
	c := container.New()
	c.AppendNumber(1)

	// store keys
	if public {
		pubKeyData, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return tools.ErrInvalidKey
		}
		c.Append(pubKeyData)
	} else {
		privKeyData, ok := privKey.(ed25519.PrivateKey)
		if !ok {
			return tools.ErrInvalidKey
		}
		c.Append(privKeyData)
	}

	signet.SetStoredKey(c.CompileData(), public)
	return nil
}

// GenerateKey implements the ToolLogic interface.
func (ed *Ed25519) GenerateKey(signet tools.SignetInt) error {
	// define variable types for API security
	var pubKey ed25519.PublicKey
	var privKey ed25519.PrivateKey
	var err error

	// generate keys
	pubKey, privKey, err = ed25519.GenerateKey(ed.Helper().Random())
	if err != nil {
		return err
	}

	signet.SetLoadedKeys(pubKey, privKey)
	return nil
}

// BurnKey implements the ToolLogic interface. This is currently ineffective, see known issues in the project's README.
func (ed *Ed25519) BurnKey(signet tools.SignetInt) error {
	pubKey := signet.PublicKey()
	privKey := signet.PrivateKey()

	// burn public key
	if pubKey != nil {
		data, ok := pubKey.([]byte)
		if ok {
			ed.Helper().Burn(data)
		}
	}

	// burn private key
	if privKey != nil {
		data, ok := privKey.([]byte)
		if ok {
			ed.Helper().Burn(data)
		}
	}

	return nil
}
