package jess

import (
	"errors"
	"fmt"
	"sync"
)

// TrustStore filter options.
const (
	FilterAny uint8 = iota
	FilterSignetOnly
	FilterRecipientOnly
)

// TrustStore errors.
var (
	ErrSignetNotFound   = errors.New("could not find signet")
	ErrEnvelopeNotFound = errors.New("could not find envelope")
)

// TrustStore holds a set of trusted Signets and Recipients.
type TrustStore interface {
	// GetSignet returns the Signet with the given ID.
	GetSignet(id string, recipient bool) (*Signet, error)
}

// MemTrustStore is a simple trust store using a Go map as backend.
type MemTrustStore struct {
	lock    sync.Mutex
	storage map[string]*Signet
}

// GetSignet returns the Signet with the given ID.
func (mts *MemTrustStore) GetSignet(id string, recipient bool) (*Signet, error) {
	mts.lock.Lock()
	defer mts.lock.Unlock()

	// get from storage
	signet, ok := mts.storage[makeStorageID(id, recipient)]
	if !ok {
		return nil, ErrSignetNotFound
	}

	return signet, nil
}

// StoreSignet stores a Signet in the TrustStore.
func (mts *MemTrustStore) StoreSignet(signet *Signet) error {
	// check for ID
	if signet.ID == "" {
		return errors.New("signets require an ID to be stored in a trust store")
	}

	mts.lock.Lock()
	defer mts.lock.Unlock()

	// store
	mts.storage[makeStorageID(signet.ID, signet.Public)] = signet
	return nil
}

// DeleteSignet deletes the Signet or Recipient with the given ID.
func (mts *MemTrustStore) DeleteSignet(id string, recipient bool) error {
	mts.lock.Lock()
	defer mts.lock.Unlock()

	// delete
	delete(mts.storage, makeStorageID(id, recipient))
	return nil
}

// SelectSignets returns a selection of the signets in the trust store. Results are filtered by tool/algorithm and whether it you're looking for a signet (private key) or a recipient (public key).
func (mts *MemTrustStore) SelectSignets(filter uint8, schemes ...string) ([]*Signet, error) {
	mts.lock.Lock()
	defer mts.lock.Unlock()

	var selection []*Signet //nolint:prealloc
	for _, signet := range mts.storage {
		// check signet scheme
		if len(schemes) > 0 && !stringInSlice(signet.Scheme, schemes) {
			return nil, nil
		}

		// check type filter
		switch filter {
		case FilterSignetOnly:
			if signet.Public {
				continue
			}
		case FilterRecipientOnly:
			if !signet.Public {
				continue
			}
		}

		selection = append(selection, signet)
	}

	return selection, nil
}

// NewMemTrustStore returns a new in-memory TrustStore.
func NewMemTrustStore() *MemTrustStore {
	return &MemTrustStore{
		storage: make(map[string]*Signet),
	}
}

func makeStorageID(id string, recipient bool) string {
	if recipient {
		return fmt.Sprintf("%s.recipient", id)
	}
	return fmt.Sprintf("%s.signet", id)
}

func stringInSlice(s string, a []string) bool {
	for _, entry := range a {
		if entry == s {
			return true
		}
	}
	return false
}
