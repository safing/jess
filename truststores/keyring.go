package truststores

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"

	"github.com/safing/jess"
)

const (
	keyringServiceNamePrefix = "jess:"

	keyringSelfcheckKey   = "_selfcheck"
	keyringSelfcheckValue = "!selfcheck"
)

// KeyringTrustStore is a trust store that uses the system keyring.
// It does not support listing entries, so it cannot be easily managed.
type KeyringTrustStore struct {
	serviceName string
}

// NewKeyringTrustStore returns a new keyring trust store with the given service name.
// The effect of the service name depends on the operating system.
// Read more at https://pkg.go.dev/github.com/zalando/go-keyring
func NewKeyringTrustStore(serviceName string) (*KeyringTrustStore, error) {
	krts := &KeyringTrustStore{
		serviceName: keyringServiceNamePrefix + serviceName,
	}

	// Run a self-check.
	err := keyring.Set(krts.serviceName, keyringSelfcheckKey, keyringSelfcheckValue)
	if err != nil {
		return nil, err
	}
	selfcheckReturn, err := keyring.Get(krts.serviceName, keyringSelfcheckKey)
	if err != nil {
		return nil, err
	}
	if selfcheckReturn != keyringSelfcheckValue {
		return nil, errors.New("keyring is faulty")
	}

	return krts, nil
}

// GetSignet returns the Signet with the given ID.
func (krts *KeyringTrustStore) GetSignet(id string, recipient bool) (*jess.Signet, error) {
	// Build ID.
	if recipient {
		id += recipientSuffix
	} else {
		id += signetSuffix
	}

	// Get data from keyring.
	data, err := keyring.Get(krts.serviceName, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", jess.ErrSignetNotFound, err)
	}

	// Parse and return.
	return jess.SignetFromBase58(data)
}

// StoreSignet stores a Signet.
func (krts *KeyringTrustStore) StoreSignet(signet *jess.Signet) error {
	// Build ID.
	var id string
	if signet.Public {
		id = signet.ID + recipientSuffix
	} else {
		id = signet.ID + signetSuffix
	}

	// Serialize.
	data, err := signet.ToBase58()
	if err != nil {
		return err
	}

	// Save to keyring.
	return keyring.Set(krts.serviceName, id, data)
}

// DeleteSignet deletes the Signet or Recipient with the given ID.
func (krts *KeyringTrustStore) DeleteSignet(id string, recipient bool) error {
	// Build ID.
	if recipient {
		id += recipientSuffix
	} else {
		id += signetSuffix
	}

	// Delete from keyring.
	return keyring.Delete(krts.serviceName, id)
}

// SelectSignets returns a selection of the signets in the trust store. Results are filtered by tool/algorithm and whether it you're looking for a signet (private key) or a recipient (public key).
func (krts *KeyringTrustStore) SelectSignets(filter uint8, schemes ...string) ([]*jess.Signet, error) {
	return nil, ErrNotSupportedByTrustStore
}

// GetEnvelope returns the Envelope with the given name.
func (krts *KeyringTrustStore) GetEnvelope(name string) (*jess.Envelope, error) {
	// Build ID.
	name += envelopeSuffix

	// Get data from keyring.
	data, err := keyring.Get(krts.serviceName, name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", jess.ErrEnvelopeNotFound, err)
	}

	// Parse and return.
	return jess.EnvelopeFromBase58(data)
}

// StoreEnvelope stores an Envelope.
func (krts *KeyringTrustStore) StoreEnvelope(envelope *jess.Envelope) error {
	// Build ID.
	name := envelope.Name + envelopeSuffix

	// Serialize.
	data, err := envelope.ToBase58()
	if err != nil {
		return err
	}

	// Save to keyring.
	return keyring.Set(krts.serviceName, name, data)
}

// DeleteEnvelope deletes the Envelope with the given name.
func (krts *KeyringTrustStore) DeleteEnvelope(name string) error {
	// Build ID.
	name += envelopeSuffix

	// Delete from keyring.
	return keyring.Delete(krts.serviceName, name)
}

// AllEnvelopes returns all envelopes.
func (krts *KeyringTrustStore) AllEnvelopes() ([]*jess.Envelope, error) {
	return nil, ErrNotSupportedByTrustStore
}
