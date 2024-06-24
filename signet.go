package jess

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mr-tron/base58"
	uuid "github.com/satori/go.uuid"

	"github.com/safing/jess/tools"
	"github.com/safing/structures/dsd"
)

// Special signet types.
const (
	SignetSchemePassword = "pw"
	SignetSchemeKey      = "key"
)

// Signet describes a cryptographic key pair. Passwords and Keys may also be wrapped in a Signet for easier integration.
type Signet struct { //nolint:maligned // TODO
	Version uint8
	ID      string
	Scheme  string

	Key        []byte
	Public     bool      `json:",omitempty"` // key is the public part of a key pair
	Protection *Envelope `json:",omitempty"` // key is a serialized letter

	// Metadata about Signet
	Info *SignetInfo `json:",omitempty"`

	// Signature of Version, Scheme, Key, Public, Protected, Info
	Signature *Letter `json:",omitempty"`

	// cache
	tool             *tools.Tool
	loadedPublicKey  crypto.PublicKey
	loadedPrivateKey crypto.PrivateKey
}

// SignetInfo holds human readable meta information about a signet.
type SignetInfo struct {
	Name    string
	Owner   string
	Created time.Time
	Expires time.Time

	Details [][2]string
}

// NewSignetBase creates a new signet base without a key.
func NewSignetBase(tool *tools.Tool) *Signet {
	return &Signet{
		Version: 1,
		Scheme:  tool.Info.Name,
		tool:    tool,
	}
}

// GenerateSignet returns a new signet with a freshly generated key.
func GenerateSignet(toolID string, securityLevel int) (*Signet, error) {
	tool, err := tools.Get(toolID)
	if err != nil {
		return nil, err
	}

	// generate signet
	signet := NewSignetBase(tool)
	err = signet.GenerateKey()
	if err != nil {
		return nil, err
	}

	return signet, nil
}

// GenerateKey generates a new key. Will not operate if key is already present.
func (signet *Signet) GenerateKey() error {
	// check if there already is a key
	if len(signet.Key) > 0 ||
		signet.loadedPrivateKey != nil ||
		signet.loadedPublicKey != nil {
		return errors.New("cannot generate key: key already present")
	}

	// load tool
	err := signet.loadTool()
	if err != nil {
		return err
	}

	// check if tool support Signets
	switch signet.tool.Info.Purpose {
	case tools.PurposeKeyExchange,
		tools.PurposeKeyEncapsulation,
		tools.PurposeSigning:
		// uses signets!
	default:
		return fmt.Errorf("tool %s does not use signets", signet.tool.Info.Name)
	}

	// generate key
	return signet.tool.StaticLogic.GenerateKey(signet)
}

// GetStoredKey returns the stored key and whether it is public.
func (signet *Signet) GetStoredKey() (key []byte, public bool) {
	return signet.Key, signet.Public
}

// SetStoredKey sets a new stored key and whether it is public.
func (signet *Signet) SetStoredKey(key []byte, public bool) {
	signet.Key = key
	signet.Public = public
}

// PublicKey returns the public key.
func (signet *Signet) PublicKey() crypto.PublicKey {
	return signet.loadedPublicKey
}

// PrivateKey returns the private key or nil, if there is none.
func (signet *Signet) PrivateKey() crypto.PrivateKey {
	return signet.loadedPrivateKey
}

// SetLoadedKeys sets the loaded public and private keys.
func (signet *Signet) SetLoadedKeys(pubKey crypto.PublicKey, privKey crypto.PrivateKey) {
	signet.loadedPublicKey = pubKey
	signet.loadedPrivateKey = privKey
}

// AsRecipient returns a public version of the Signet.
func (signet *Signet) AsRecipient() (*Signet, error) {
	// Check special signet schemes.
	switch signet.Scheme {
	case SignetSchemeKey:
		return nil, errors.New("keys cannot be a recipient")
	case SignetSchemePassword:
		return nil, errors.New("passwords cannot be a recipient")
	}

	// load so we can split keys
	err := signet.LoadKey()
	if err != nil {
		return nil, err
	}

	return &Signet{
		Version:          signet.Version,
		ID:               signet.ID,
		Scheme:           signet.Scheme,
		Key:              nil,  // do not copy serialized key
		Public:           true, // mark explicitly as public
		Protection:       nil,  // remove protection
		Info:             signet.Info,
		Signature:        nil, // remove signature, as it would be invalid
		tool:             signet.tool,
		loadedPublicKey:  signet.loadedPublicKey,
		loadedPrivateKey: nil, // remove private key
	}, nil
}

// LoadKey loads the serialized key pair.
func (signet *Signet) LoadKey() error {
	// check if already loaded
	if signet.loadedPublicKey != nil {
		return nil
	}

	// check if protected
	if signet.Protection != nil {
		return tools.ErrProtected
	}

	// load tool
	err := signet.loadTool()
	if err != nil {
		return err
	}

	return signet.tool.StaticLogic.LoadKey(signet)
}

// Tool returns the tool of the signet.
func (signet *Signet) Tool() (*tools.Tool, error) {
	// load tool
	err := signet.loadTool()
	if err != nil {
		return nil, err
	}

	return signet.tool, nil
}

// loadTool gets and caches the tool for the signet.
func (signet *Signet) loadTool() error {
	if signet.tool != nil {
		return nil
	}

	tool, err := tools.Get(signet.Scheme)
	if err != nil {
		return err
	}

	signet.tool = tool
	return nil
}

// StoreKey serializes the loaded key pair.
func (signet *Signet) StoreKey() error {
	// check if already stored
	if len(signet.Key) != 0 {
		return nil
	}

	// load tool
	err := signet.loadTool()
	if err != nil {
		return err
	}

	return signet.tool.StaticLogic.StoreKey(signet)
}

// Verify verifies the signature of the signet.
func (signet *Signet) Verify() error {
	// TODO
	return errors.New("signet verification not yet implemented")
}

// Burn destroys all the key material and renders the Signet unusable. This is currently ineffective, see known issues in the project's README.
func (signet *Signet) Burn() error {
	// load tool
	err := signet.loadTool()
	if err != nil {
		return err
	}

	return signet.tool.StaticLogic.BurnKey(signet)
}

// AssignUUID generates a (new) UUID for the Signet.
func (signet *Signet) AssignUUID() error {
	// generate UUID v4
	u := uuid.UUID{}
	_, err := io.ReadFull(Random(), u[:])
	if err != nil {
		return err
	}

	u.SetVersion(uuid.V4)
	u.SetVariant(uuid.VariantRFC4122)
	signet.ID = u.String()
	return nil
}

// ToBytes serializes the Signet to a byte slice.
func (signet *Signet) ToBytes() ([]byte, error) {
	// Make sure the key is stored in the serializable format.
	if err := signet.StoreKey(); err != nil {
		return nil, fmt.Errorf("failed to serialize the key: %w", err)
	}

	// Serialize Signet.
	data, err := dsd.Dump(signet, dsd.CBOR)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize the signet: %w", err)
	}

	return data, nil
}

// SignetFromBytes parses and loads a serialized signet.
func SignetFromBytes(data []byte) (*Signet, error) {
	signet := &Signet{}

	// Parse Signet from data.
	if _, err := dsd.Load(data, signet); err != nil {
		return nil, fmt.Errorf("failed to parse data format: %w", err)
	}

	// Load the key.
	if err := signet.LoadKey(); err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return signet, nil
}

// ToBase58 serializes the signet and encodes it with base58.
func (signet *Signet) ToBase58() (string, error) {
	// Serialize Signet.
	data, err := signet.ToBytes()
	if err != nil {
		return "", err
	}

	// Encode and return.
	return base58.Encode(data), nil
}

// SignetFromBase58 parses and loads a base58 encoded serialized signet.
func SignetFromBase58(base58Encoded string) (*Signet, error) {
	// Decode string.
	data, err := base58.Decode(base58Encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base58: %w", err)
	}

	// Parse and return.
	return SignetFromBytes(data)
}
