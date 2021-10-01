package truststores

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/safing/jess"
)

const (
	signetSuffix        = ".signet"
	recipientSuffix     = ".recipient"
	envelopeSuffix      = ".envelope"
	permittedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789- ._+@"
)

// TrustStore errors.
var (
	errInvalidSignetIDChars     = fmt.Errorf("this trust store only allows these characters in signet IDs: %s", permittedCharacters)
	errInvalidEnvelopeNameChars = fmt.Errorf("this trust store only allows these characters in envelope names: %s", permittedCharacters)
)

// DirTrustStore is a simple trust store using a filesystem directory as the storage backend.
type DirTrustStore struct {
	lock       sync.Mutex
	storageDir string
}

// GetSignet returns the Signet with the given ID.
func (dts *DirTrustStore) GetSignet(id string, recipient bool) (*jess.Signet, error) {
	// check ID
	ok := NamePlaysNiceWithFS(id)
	if !ok {
		return nil, errInvalidSignetIDChars
	}

	// synchronize fs access
	dts.lock.Lock()
	defer dts.lock.Unlock()

	// read from storage
	filename := filepath.Join(dts.storageDir, makeStorageID(id, recipient))
	signet, err := LoadSignetFromFile(filename)
	if err != nil {
		return nil, err
	}

	return signet, nil
}

// StoreSignet stores a Signet in the TrustStore.
func (dts *DirTrustStore) StoreSignet(signet *jess.Signet) error {
	// synchronize fs access
	dts.lock.Lock()
	defer dts.lock.Unlock()

	// write
	filename := filepath.Join(dts.storageDir, makeStorageID(signet.ID, signet.Public))
	return WriteSignetToFile(signet, filename)
}

// DeleteSignet deletes the Signet or Recipient with the given ID.
func (dts *DirTrustStore) DeleteSignet(id string, recipient bool) error {
	// check ID
	ok := NamePlaysNiceWithFS(id)
	if !ok {
		return errInvalidSignetIDChars
	}

	// synchronize fs access
	dts.lock.Lock()
	defer dts.lock.Unlock()

	// delete
	filename := filepath.Join(dts.storageDir, makeStorageID(id, recipient))
	return os.Remove(filename)
}

// SelectSignets returns a selection of the signets in the trust store. Results are filtered by tool/algorithm and whether it you're looking for a signet (private key) or a recipient (public key).
func (dts *DirTrustStore) SelectSignets(filter uint8, schemes ...string) ([]*jess.Signet, error) {
	dts.lock.Lock()
	defer dts.lock.Unlock()

	var selection []*jess.Signet

	// walk the storage
	err := filepath.Walk(dts.storageDir, func(path string, info os.FileInfo, err error) error {
		// consider errors
		if err != nil {
			return err
		}

		// skip dirs
		if info.IsDir() {
			return nil
		}

		// check for suffix
		if !strings.HasSuffix(path, signetSuffix) &&
			!strings.HasSuffix(path, recipientSuffix) {
			return nil
		}

		signet, err := LoadSignetFromFile(path)
		if err != nil {
			// add failed signet to list
			selection = append(selection, &jess.Signet{
				Info: &jess.SignetInfo{
					Name: "[failed to load]",
				},
				ID:     strings.Split(filepath.Base(path), ".")[0],
				Public: strings.HasSuffix(path, recipientSuffix),
			})
			return nil
		}

		// check signet scheme
		if len(schemes) > 0 && !stringInSlice(signet.Scheme, schemes) {
			return nil
		}

		// check type filter
		switch filter {
		case jess.FilterSignetOnly:
			if signet.Public {
				return nil
			}
		case jess.FilterRecipientOnly:
			if !signet.Public {
				return nil
			}
		}

		selection = append(selection, signet)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access trust store entry: %s", err)
	}

	return selection, nil
}

// GetEnvelope returns the Envelope with the given name.
func (dts *DirTrustStore) GetEnvelope(name string) (*jess.Envelope, error) {
	// check name
	ok := NamePlaysNiceWithFS(name)
	if !ok {
		return nil, errInvalidEnvelopeNameChars
	}

	// synchronize fs access
	dts.lock.Lock()
	defer dts.lock.Unlock()

	// read from storage
	filename := filepath.Join(dts.storageDir, name+envelopeSuffix)
	envelope, err := LoadEnvelopeFromFile(filename)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

// StoreEnvelope stores an Envelope.
func (dts *DirTrustStore) StoreEnvelope(envelope *jess.Envelope) error {
	// synchronize fs access
	dts.lock.Lock()
	defer dts.lock.Unlock()

	// write
	filename := filepath.Join(dts.storageDir, envelope.Name+envelopeSuffix)
	return WriteEnvelopeToFile(envelope, filename)
}

// DeleteEnvelope deletes the Envelope with the given name.
func (dts *DirTrustStore) DeleteEnvelope(name string) error {
	// check name
	ok := NamePlaysNiceWithFS(name)
	if !ok {
		return errInvalidEnvelopeNameChars
	}

	// synchronize fs access
	dts.lock.Lock()
	defer dts.lock.Unlock()

	// delete
	filename := filepath.Join(dts.storageDir, name+envelopeSuffix)
	return os.Remove(filename)
}

// AllEnvelopes returns all envelopes.
func (dts *DirTrustStore) AllEnvelopes() ([]*jess.Envelope, error) {
	dts.lock.Lock()
	defer dts.lock.Unlock()

	var all []*jess.Envelope

	// walk the storage
	err := filepath.Walk(dts.storageDir, func(path string, info os.FileInfo, err error) error {
		// consider errors
		if err != nil {
			return err
		}

		// skip dirs
		if info.IsDir() {
			return nil
		}

		// check for suffix
		if !strings.HasSuffix(path, envelopeSuffix) {
			return nil
		}

		envelope, err := LoadEnvelopeFromFile(path)
		if err != nil {
			// add failed envelope to list
			all = append(all, &jess.Envelope{
				Name: fmt.Sprintf("%s [failed to load]",
					strings.TrimSuffix(filepath.Base(path), envelopeSuffix)),
			})
			return nil
		}

		all = append(all, envelope)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access trust store entry: %s", err)
	}

	return all, nil
}

// NewDirTrustStore returns a new trust store using a filesystem directory as the storage backend.
func NewDirTrustStore(storageDir string) (*DirTrustStore, error) {
	cleanedPath := filepath.Clean(storageDir)

	// validate path
	info, err := os.Stat(cleanedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("trust store does not exist: %s", err)
		}
		return nil, fmt.Errorf("failed to access trust store: %s", err)
	}
	if !info.IsDir() {
		return nil, errors.New("truststore storage dir is a file, not a directory")
	}

	return &DirTrustStore{
		storageDir: cleanedPath,
	}, nil
}

// NamePlaysNiceWithFS checks if the given string plays nice with filesystems.
func NamePlaysNiceWithFS(s string) (ok bool) {
	for _, c := range s {
		n := countRuneInString(permittedCharacters, c)
		if n == 0 {
			return false
		}
	}
	return true
}

func countRuneInString(s string, r rune) (n int) {
	for {
		i := strings.IndexRune(s, r)
		if i < 0 {
			return
		}
		n++
		s = s[i+1:]
	}
}

func makeStorageID(id string, recipient bool) string {
	if recipient {
		return id + recipientSuffix
	}
	return id + signetSuffix
}
