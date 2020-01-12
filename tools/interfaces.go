package tools

import (
	"crypto"
	"io"
)

// HelperInt is an interface to Helper.
type HelperInt interface {
	// NewSessionKey returns a new session key (or nonce) in tool's specified length.
	NewSessionKey() ([]byte, error)

	// FillNewSessionKey fills the given []byte slice with a new session key (or nonce).
	FillNewSessionKey(key []byte) error

	// NewSessionNonce returns a new session nonce in tool's specified length.
	NewSessionNonce() ([]byte, error)

	// Random returns the io.Reader for reading randomness.
	Random() io.Reader

	// RandomBytes returns the specified amount of random bytes in a []byte slice.
	RandomBytes(n int) ([]byte, error)

	// Burn gets rid of the given []byte slice(s).
	Burn(data ...[]byte)

	// DefaultSymmetricKeySize returns the default key size for this session.
	DefaultSymmetricKeySize() int

	// SecurityLevel returns the effective (ie. lowest) security level for this session.
	SecurityLevel() int

	// MaxSecurityLevel returns the (highest) security level for this session.
	MaxSecurityLevel() int
}

// SignetInt is a minimal interface to Signet.
type SignetInt interface {
	// GetStoredKey returns the stored key and whether it is public.
	GetStoredKey() (key []byte, public bool)

	// SetStoredKey sets a new stored key and whether it is public.
	SetStoredKey(new []byte, public bool)

	// PublicKey returns the public key.
	PublicKey() crypto.PublicKey

	// PrivateKey returns the private key or nil, if there is none.
	PrivateKey() crypto.PrivateKey

	// SetLoadedKeys sets the loaded public and private keys.
	SetLoadedKeys(pubKey crypto.PublicKey, privKey crypto.PrivateKey)

	// LoadKey loads the serialized key pair.
	LoadKey() error
}
