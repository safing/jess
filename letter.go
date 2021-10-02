// Container versions
//
// 1: for network, simple
// 2: for storage
// 3: for network, concealed (TBD)

package jess

import (
	"encoding/json"
	"fmt"

	"github.com/safing/portbase/container"
	"github.com/safing/portbase/formats/dsd"
)

// Letter is the data format for encrypted data at rest or in transit.
type Letter struct { //nolint:maligned // TODO
	Version uint8  // signed, MAC'd (may not exist when wired)
	SuiteID string // signed, MAC'd (may not exist when wired)

	Nonce []byte  // signed, MAC'd
	Keys  []*Seal `json:",omitempty"` // signed, MAC'd

	Data       []byte  `json:",omitempty"` // signed, MAC'd
	Mac        []byte  `json:",omitempty"` // signed
	Signatures []*Seal `json:",omitempty"`

	// Flags for wire protocol
	ApplyKeys bool `json:",omitempty"` // MAC'd
}

// Seal holds a key, key exchange or signature within a letter.
type Seal struct {
	Scheme string `json:",omitempty"`

	// Key Establishment: Signet ID of recipient's signet
	// Signature: Signet ID of signer's signet
	ID string `json:",omitempty"`

	// Key Establishment: Public key or wrapped key
	// Signature: Signature value
	Value []byte `json:",omitempty"`
}

// Envelope returns an envelope built from the letter, configured for opening it.
func (letter *Letter) Envelope(requirements *Requirements) (*Envelope, error) {
	// basic checks
	if letter.Version == 0 {
		return nil, fmt.Errorf("letter does not specify version")
	}
	if len(letter.SuiteID) == 0 {
		return nil, fmt.Errorf("letter does not specify a suite")
	}

	// create envelope
	e := &Envelope{
		Version: letter.Version,
		SuiteID: letter.SuiteID,
	}

	// get and check suite
	err := e.LoadSuite()
	if err != nil {
		return nil, err
	}
	// default to full requirements
	if requirements == nil {
		requirements = NewRequirements()
	}
	// check suite against requirements
	err = e.suite.Provides.CheckComplianceTo(requirements)
	if err != nil {
		return nil, err
	}

	for _, seal := range letter.Keys {
		// handshake messages have ephermal encapsulation keys in first message
		if len(seal.ID) > 0 {
			if seal.Scheme == SignetSchemeKey || seal.Scheme == SignetSchemePassword {
				e.Secrets = append(e.Secrets, &Signet{
					Version: letter.Version,
					ID:      seal.ID,
					Scheme:  seal.Scheme,
				})
			} else {
				e.Recipients = append(e.Recipients, &Signet{
					Version: letter.Version,
					ID:      seal.ID,
					Scheme:  seal.Scheme,
				})
			}
		}
	}
	for _, seal := range letter.Signatures {
		e.Senders = append(e.Senders, &Signet{
			Version: letter.Version,
			ID:      seal.ID,
			Scheme:  seal.Scheme,
		})
	}

	e.opening = true
	return e, nil
}

// Open creates a session and opens the letter in one step.
func (letter *Letter) Open(requirements *Requirements, trustStore TrustStore) ([]byte, error) {
	e, err := letter.Envelope(requirements)
	if err != nil {
		return nil, err
	}

	s, err := e.Correspondence(trustStore)
	if err != nil {
		return nil, err
	}

	return s.Open(letter)
}

// Verify creates a session and verifies the letter in one step.
func (letter *Letter) Verify(requirements *Requirements, trustStore TrustStore) error {
	e, err := letter.Envelope(requirements)
	if err != nil {
		return err
	}

	s, err := e.initCorrespondence(trustStore, true)
	if err != nil {
		return err
	}

	return s.Verify(letter)
}

// WireCorrespondence creates a wire session (communication over a network connection) from a letter.
func (letter *Letter) WireCorrespondence(trustStore TrustStore) (*Session, error) {
	e, err := letter.Envelope(NewRequirements().Remove(SenderAuthentication))
	if err != nil {
		return nil, err
	}

	return e.WireCorrespondence(trustStore)
}

// ToJSON serializes the letter to json.
func (letter *Letter) ToJSON() ([]byte, error) {
	return json.Marshal(letter)
}

// LetterFromJSON loads a json-serialized letter.
func LetterFromJSON(data []byte) (*Letter, error) {
	letter := &Letter{}

	err := json.Unmarshal(data, letter)
	if err != nil {
		return nil, err
	}

	return letter, nil
}

// ToDSD serializes the letter to the given dsd format.
func (letter *Letter) ToDSD(dsdFormat uint8) ([]byte, error) {
	data, err := dsd.Dump(letter, dsdFormat)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// LetterFromDSD loads a dsd-serialized letter.
func LetterFromDSD(data []byte) (*Letter, error) {
	letter := &Letter{}

	_, err := dsd.Load(data, letter)
	if err != nil {
		return nil, err
	}

	return letter, nil
}

const (
	// Field IDs for signing
	// These IDs MUST NOT CHANGE.

	fieldIDLetterVersion uint64 = 1 // signed, MAC'd (may not exist when wired)
	fieldIDLetterSuiteID uint64 = 2 // signed, MAC'd (may not exist when wired)
	fieldIDLetterNonce   uint64 = 3 // signed, MAC'd
	fieldIDLetterKeys    uint64 = 4 // signed, MAC'd
	fieldIDLetterMac     uint64 = 5 // signed

	fieldIDSealScheme uint64 = 16 // signed, MAC'd
	fieldIDSealID     uint64 = 17 // signed, MAC'd
	fieldIDSealValue  uint64 = 18 // signed, MAC'd
)

func (letter *Letter) compileAssociatedData() []byte {
	// every field is transformed and prepended with a static ID
	// this makes it easy to stay backward compatible without hassling around with versioning when fields are added

	c := container.New()

	if letter.Version > 0 {
		c.AppendNumber(fieldIDLetterVersion) // append field ID
		c.AppendNumber(uint64(letter.Version))
	}
	if len(letter.SuiteID) > 0 {
		c.AppendNumber(fieldIDLetterSuiteID)    // append field ID
		c.AppendAsBlock([]byte(letter.SuiteID)) // append field content with length
	}
	if len(letter.Nonce) > 0 {
		c.AppendNumber(fieldIDLetterNonce) // append field ID
		c.AppendAsBlock(letter.Nonce)      // append field content with length
	}
	if len(letter.Keys) > 0 {
		c.AppendNumber(fieldIDLetterKeys) // append field ID
		c.AppendInt(len(letter.Keys))     // append number of keys
		for i, seal := range letter.Keys {
			c.AppendInt(i)                // append index
			seal.compileAssociatedData(c) // append field content with length
		}
	}

	return c.CompileData()
}

func (letter *Letter) compileAssociatedSigningData(associatedData []byte) []byte {
	// compile basic associated data if not yet done
	if len(associatedData) == 0 {
		associatedData = letter.compileAssociatedData()
	}

	// return if there is no Mac
	if len(letter.Mac) == 0 {
		return associatedData
	}

	// add Mac to associated data and return
	c := container.New(associatedData)
	c.AppendNumber(fieldIDLetterMac) // append field ID
	c.AppendAsBlock(letter.Mac)      // append field content with length

	return c.CompileData()
}

func (seal *Seal) compileAssociatedData(c *container.Container) {
	if seal.Scheme != "" {
		c.AppendNumber(fieldIDSealScheme)    // append field ID
		c.AppendAsBlock([]byte(seal.Scheme)) // append field content with length
	}
	if seal.ID != "" {
		c.AppendNumber(fieldIDSealID)    // append field ID
		c.AppendAsBlock([]byte(seal.ID)) // append field content with length
	}
	if len(seal.Value) > 0 {
		c.AppendNumber(fieldIDSealValue) // append field ID
		c.AppendAsBlock(seal.Value)      // append field content with length
	}
}
