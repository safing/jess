package jess

import (
	"errors"
	"io"

	"github.com/safing/jess/tools"
)

var (
	errNoSession = errors.New("helper is used outside of session")
	errNoKDF     = errors.New("session has no key derivation tool")
)

// Helper provides a basic interface for tools to access session properties and functionality.
type Helper struct {
	session *Session
	info    *tools.ToolInfo
}

// NewSessionKey returns a new session key in tool's specified length.
func (h *Helper) NewSessionKey() ([]byte, error) {
	if h.session == nil {
		return nil, errNoSession
	}
	if h.session.kdf == nil {
		return nil, errNoKDF
	}

	if h.info.KeySize > 0 {
		return h.session.kdf.DeriveKey(h.info.KeySize)
	}
	return h.session.kdf.DeriveKey(h.session.DefaultSymmetricKeySize)
}

// FillNewSessionKey fills the given []byte slice with a new session key (or nonce).
func (h *Helper) FillNewSessionKey(key []byte) error {
	if h.session == nil {
		return errNoSession
	}
	if h.session.kdf == nil {
		return errNoKDF
	}

	return h.session.kdf.DeriveKeyWriteTo(key)
}

// NewSessionNonce returns a new session nonce in tool's specified length.
func (h *Helper) NewSessionNonce() ([]byte, error) {
	if h.session == nil {
		return nil, errNoSession
	}
	if h.session.kdf == nil {
		return nil, errNoKDF
	}

	if h.info.NonceSize > 0 {
		return h.session.kdf.DeriveKey(h.info.NonceSize)
	}
	return h.session.kdf.DeriveKey(h.session.DefaultSymmetricKeySize)
}

// Random returns the io.Reader for reading randomness.
func (h *Helper) Random() io.Reader {
	return Random()
}

// RandomBytes returns the specified amount of random bytes in a []byte slice.
func (h *Helper) RandomBytes(n int) ([]byte, error) {
	return RandomBytes(n)
}

// Burn gets rid of the given []byte slice(s). This is currently ineffective, see known issues in the project's README.
func (h *Helper) Burn(data ...[]byte) {
	Burn(data...)
}

// DefaultSymmetricKeySize returns the default key size for this session.
func (h *Helper) DefaultSymmetricKeySize() int {
	if h.session != nil && h.session.DefaultSymmetricKeySize > 0 {
		return h.session.DefaultSymmetricKeySize
	}
	return defaultSymmetricKeySize
}

// SecurityLevel returns the effective (ie. lowest) security level for this session.
func (h *Helper) SecurityLevel() int {
	if h.session != nil && h.session.SecurityLevel > 0 {
		return h.session.SecurityLevel
	}
	return defaultSecurityLevel
}

// MaxSecurityLevel returns the (highest) security level for this session.
func (h *Helper) MaxSecurityLevel() int {
	if h.session != nil && h.session.maxSecurityLevel > 0 {
		return h.session.maxSecurityLevel
	}
	return defaultSecurityLevel
}

// Burn gets rid of the given []byte slice(s). This is currently ineffective, see known issues in the project's README.
func Burn(data ...[]byte) {
	for _, slice := range data {
		for i := 0; i < len(slice); i++ {
			slice[i] = 0xFF
		}
	}
}
