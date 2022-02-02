package truststores

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/safing/jess"
	"github.com/safing/portbase/formats/dsd"
)

// WriteSignetToFile serializes the signet and writes it to the given file.
func WriteSignetToFile(signet *jess.Signet, filename string) error {
	// check ID
	if signet.ID == "" {
		return errors.New("signets require an ID to be stored in a trust store")
	}
	ok := NamePlaysNiceWithFS(signet.ID)
	if !ok {
		return errInvalidSignetIDChars
	}

	// serialize
	data, err := dsd.DumpIndent(signet, dsd.JSON, "\t")
	if err != nil {
		return err
	}

	// write
	err = ioutil.WriteFile(filename, data, 0o0600)
	if err != nil {
		return err
	}

	return nil
}

// LoadSignetFromFile loads a signet from the given filepath.
func LoadSignetFromFile(filename string) (*jess.Signet, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, jess.ErrSignetNotFound
		}
		return nil, err
	}

	signet := &jess.Signet{}
	_, err = dsd.Load(data, signet)
	if err != nil {
		return nil, err
	}

	return signet, nil
}

// WriteEnvelopeToFile serializes the envelope and writes it to the given file.
func WriteEnvelopeToFile(envelope *jess.Envelope, filename string) error {
	// check name
	if envelope.Name == "" {
		return errors.New("envelopes require a name to be stored in a trust store")
	}
	ok := NamePlaysNiceWithFS(envelope.Name)
	if !ok {
		return errInvalidEnvelopeNameChars
	}

	// serialize
	data, err := dsd.DumpIndent(envelope, dsd.JSON, "\t")
	if err != nil {
		return err
	}

	// write to storage
	err = ioutil.WriteFile(filename, data, 0600) //nolint:gofumpt // gofumpt is ignorant of octal numbers.
	if err != nil {
		return err
	}

	return nil
}

// LoadEnvelopeFromFile loads an envelope from the given filepath.
func LoadEnvelopeFromFile(filename string) (*jess.Envelope, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, jess.ErrEnvelopeNotFound
		}
		return nil, err
	}

	// load envelope
	envelope := &jess.Envelope{}
	_, err = dsd.Load(data, envelope)
	if err != nil {
		return nil, err
	}

	// load suite using SuiteID
	err = envelope.LoadSuite()
	if err != nil {
		return nil, err
	}

	return envelope, nil
}
