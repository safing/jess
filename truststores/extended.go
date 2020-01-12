package truststores

import (
	"github.com/safing/jess"
)

// ExtendedTrustStore holds a set of trusted Signets, Recipients and Envelopes.
type ExtendedTrustStore interface {
	jess.TrustStore

	// GetSignet returns the Signet with the given ID.
	// GetSignet(id string, recipient bool) (*Signet, error)

	// StoreSignet stores a Signet.
	StoreSignet(signet *jess.Signet) error

	// DeleteSignet deletes the Signet or Recipient with the given ID.
	DeleteSignet(id string, recipient bool) error

	// SelectSignets returns a selection of the signets in the trust store. Results are filtered by tool/algorithm and whether it you're looking for a signet (private key) or a recipient (public key).
	SelectSignets(filter uint8, schemes ...string) ([]*jess.Signet, error)

	// GetEnvelope returns the Envelope with the given name.
	GetEnvelope(name string) (*jess.Envelope, error)

	// StoreEnvelope stores an Envelope.
	StoreEnvelope(envelope *jess.Envelope) error

	// DeleteEnvelope deletes the Envelope with the given name.
	DeleteEnvelope(name string) error

	// AllEnvelopes returns all envelopes.
	AllEnvelopes() ([]*jess.Envelope, error)
}
