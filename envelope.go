package jess

import (
	"errors"
	"fmt"
)

// Envelope holds configuration for jess to put data into a letter.
type Envelope struct { //nolint:maligned // TODO
	Version uint8
	Name    string
	Tools   []string

	// Secret keys and passwords
	Secrets []*Signet

	// Sender related signets
	// When closing: private keys for signatures
	// When opening: public keys for signatures
	Senders []*Signet

	// Recipient related signets
	// When closing: public keys for key exchange or key encapsulation
	// When opening: private keys for key exchange or key encapsulation
	Recipients []*Signet

	// For users, envelopes describe how a letter is closed.
	// Therefore Secrets and Senders always refer to private keys and Recipients to public keys in that context.
	// These distictions are important in order for the user to easily and confidently distinguish what is going to happen. Think of it as "human security".

	MinimumSecurityLevel int
	No                   string
	requirements         *Requirements

	// flag to signify if envelope is used for opening
	opening bool
}

// NewUnconfiguredEnvelope returns an unconfigured, but slightly initialized envelope.
func NewUnconfiguredEnvelope() *Envelope {
	e := &Envelope{
		Version:      1,
		requirements: NewRequirements(),
	}
	e.SerializeRequirements()
	return e
}

// Correspondence returns a new session configured with the envelope.
func (e *Envelope) Correspondence(trustStore TrustStore) (*Session, error) {
	return e.initCorrespondence(trustStore, false)
}

func (e *Envelope) initCorrespondence(trustStore TrustStore, verifying bool) (*Session, error) {
	err := e.LoadRequirements()
	if err != nil {
		return nil, err
	}

	if verifying {
		// prep sender signets only
		err = e.prepSignets(e.Senders, e.opening, trustStore)
	} else {
		// prep all signets
		err = e.PrepareSignets(trustStore)
	}
	if err != nil {
		return nil, err
	}

	return newSession(e)
}

// WireCorrespondence returns a new wire session (live communication) configured with the envelope.
func (e *Envelope) WireCorrespondence(trustStore TrustStore) (*Session, error) {
	s, err := e.Correspondence(trustStore)
	if err != nil {
		return nil, err
	}

	err = s.initWireSession()
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Check returns whether the envelope is valid and can be used as is.
func (e *Envelope) Check(trustStore TrustStore) error {
	_, err := e.Correspondence(trustStore)
	return err
}

// NoRecipientAuth removes the requirement to authenticate the recipient.
func (e *Envelope) NoRecipientAuth() *Envelope {
	if e.requirements == nil {
		e.requirements = NewRequirements()
	}

	e.requirements.Remove(RecipientAuthentication)
	return e
}

// NoSenderAuth removes the requirement to authenticate the sender.
func (e *Envelope) NoSenderAuth() *Envelope {
	if e.requirements == nil {
		e.requirements = NewRequirements()
	}

	e.requirements.Remove(SenderAuthentication)
	e.SerializeRequirements()
	return e
}

// NoConfidentiality removes the requirement to provide confidentiality.
func (e *Envelope) NoConfidentiality() *Envelope {
	if e.requirements == nil {
		e.requirements = NewRequirements()
	}

	e.requirements.Remove(Confidentiality)
	e.SerializeRequirements()
	return e
}

// NoIntegrity removes the requirement to provide integrity.
func (e *Envelope) NoIntegrity() *Envelope {
	if e.requirements == nil {
		e.requirements = NewRequirements()
	}

	e.requirements.Remove(Integrity)
	e.SerializeRequirements()
	return e
}

// Unsafe removes all requirements.
func (e *Envelope) Unsafe() *Envelope {
	e.requirements = &Requirements{}
	e.SerializeRequirements()
	return e
}

// Requirements returns the required requirements.
func (e *Envelope) Requirements() *Requirements {
	return e.requirements
}

// SetRequirements sets new requirements.
func (e *Envelope) SetRequirements(requirements *Requirements) {
	e.requirements = requirements
}

// LoadRequirements loads the required requirements from the struct's exposed negated "No" specification.
func (e *Envelope) LoadRequirements() error {
	if e.requirements == nil {
		attrs, err := ParseRequirementsFromNoSpec(e.No)
		if err != nil {
			return nil
		}

		e.requirements = attrs
	}
	return nil
}

// SerializeRequirements saves the requirement requirements in the struct's exposed negated "No" specification.
func (e *Envelope) SerializeRequirements() {
	e.No = e.requirements.SerializeToNoSpec()
}

// LoopSecrets loops over all secrets of the given scheme.
func (e *Envelope) LoopSecrets(scheme string, fn func(*Signet) error) error {
	for _, signet := range e.Secrets {
		if len(scheme) == 0 || signet.Scheme == scheme {
			err := fn(signet)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// LoopSenders loops over all sender signets of the given scheme.
func (e *Envelope) LoopSenders(scheme string, fn func(*Signet) error) error {
	for _, signet := range e.Senders {
		if len(scheme) == 0 || signet.Scheme == scheme {
			err := fn(signet)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// LoopRecipients loops over all recipient signets of the given scheme.
func (e *Envelope) LoopRecipients(scheme string, fn func(*Signet) error) error {
	for _, signet := range e.Recipients {
		if len(scheme) == 0 || signet.Scheme == scheme {
			err := fn(signet)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// PrepareSignets checks that all signets of the envelope are ready to use. It will fetch referenced signets and load the keys.
func (e *Envelope) PrepareSignets(storage TrustStore) error {
	err := e.prepSignets(e.Secrets, e.opening, storage)
	if err != nil {
		return err
	}

	err = e.prepSignets(e.Senders, e.opening, storage)
	if err != nil {
		return err
	}

	return e.prepSignets(e.Recipients, !e.opening, storage)
}

// prepSignets checks that all signets of the envelope are ready to use.
func (e *Envelope) prepSignets(signets []*Signet, recipients bool, storage TrustStore) error {
	for i, signet := range signets {
		// load from storage
		if len(signet.Key) == 0 {
			if signet.Scheme == SignetSchemePassword {
				err := fillPassword(signet, !recipients, storage, e.MinimumSecurityLevel)
				if err != nil {
					return fmt.Errorf(`failed to get password for "%s": %s`, signet.ID, err)
				}
				continue
			}

			// signet is referrer
			if len(signet.ID) == 0 {
				return errors.New("signets must have a scheme+key or an ID")
			}

			// check if we have a storage
			if storage == nil {
				return fmt.Errorf(`failed to get signet with ID "%s": no truststore provided`, signet.ID)
			}

			// get signet from trust store
			new, err := storage.GetSignet(signet.ID, recipients)
			if err != nil {
				return fmt.Errorf(`failed to get signet with ID "%s" from truststore: %s`, signet.ID, err)
			}

			// check for scheme mismatch
			if signet.Scheme != "" && signet.Scheme != new.Scheme {
				return fmt.Errorf(`failed to apply signet with ID "%s" from truststore: was expected to be of type %s, but is %s`, signet.ID, signet.Scheme, new.Scheme)
			}

			// apply signet back into envelope
			signet = new
			signets[i] = new
		}

		// unwrap protection
		if signet.Protection != nil {
			return errors.New("protected signets are not yet supported")
		}

		// load signet
		switch signet.Scheme {
		case SignetSchemeKey, SignetSchemePassword:
			// no loading needed
		default:
			err := signet.LoadKey()
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func fillPassword(signet *Signet, createPassword bool, storage TrustStore, minSecurityLevel int) (err error) {
	if createPassword {
		if createPasswordCallback == nil {
			return nil // ignore
		}
	} else if getPasswordCallback == nil {
		return nil
	}

	// find reference
	if signet.Info == nil || signet.Info.Name == "" {
		// check trust store for name
		if len(signet.ID) > 0 && storage != nil {
			// get signet from trust store
			new, err := storage.GetSignet(signet.ID, false)
			if err == nil && new.Info != nil {
				if signet.Info == nil {
					signet.Info = new.Info
				} else {
					signet.Info.Name = new.Info.Name
				}
			}
		}
	}

	if createPassword {
		return createPasswordCallback(signet, minSecurityLevel)
	}
	return getPasswordCallback(signet)
}
