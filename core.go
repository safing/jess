package jess

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/safing/portbase/container"
)

// Close encrypts (and possibly signs) the given data and returns a Letter. Storyline: Close takes an envelope, inserts the message and closes it, resulting in a letter.
func (s *Session) Close(data []byte) (*Letter, error) { //nolint:gocognit
	var err error
	var associatedData []byte
	letter := &Letter{}

	if s.wire == nil || s.wire.msgNo == 0 {
		letter.Version = s.envelope.Version
		letter.SuiteID = s.envelope.SuiteID
	}

	// Check for additional data in slice, which we should not touch.
	// TODO: Pre-allocate needed overhead for AEAD and others.
	if len(data) != cap(data) {
		// Make a copy of the data in order to not modify unrelated data.
		copiedData := make([]byte, len(data))
		copy(copiedData, data)
		data = copiedData
	}

	/////////////////
	// key management
	/////////////////

	// create nonce
	nonce, err := RandomBytes(s.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %s", err)
	}
	letter.Nonce = nonce

	if s.kdf != nil {
		// if we require a key

		// key establishment
		if s.wire != nil {
			err = s.wire.sendHandshakeAndInitKDF(letter)
			if err != nil {
				return nil, err
			}
		} else {
			keyMaterial, err := s.setupClosingKeyMaterial(letter)
			if err != nil {
				return nil, err
			}

			// init KDF
			err = s.kdf.InitKeyDerivation(letter.Nonce, keyMaterial...)
			if err != nil {
				return nil, fmt.Errorf("failed to init %s kdf: %s", s.kdf.Info().Name, err)
			}
		}

		/////////////
		// encryption
		/////////////

		// setup tools
		err = s.setup()
		if err != nil {
			return nil, err
		}
		defer s.reset() //nolint:errcheck // TODO: handle error? Currently there should be none.

		// Ciphers
		for _, tool := range s.ciphers {
			data, err = tool.Encrypt(data)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt with %s: %s", tool.Info().Name, err)
			}
		}

		// build associated data
		if len(s.integratedCiphers) > 0 || len(s.macs) > 0 {
			associatedData = letter.compileAssociatedData()
		}

		// Integrated Ciphers / AEAD
		for _, tool := range s.integratedCiphers {
			data, err = tool.AuthenticatedEncrypt(data, associatedData)
			if err != nil {
				return nil, fmt.Errorf("failed to auth-encrypt with %s: %s", tool.Info().Name, err)
			}
		}

		if len(s.macs) > 0 {
			// run managed mac hashers
			if s.managedMACHashers != nil {
				err = s.feedManagedHashers(s.managedMACHashers, data, associatedData)
				if err != nil {
					return nil, err
				}

				defer s.resetManagedHashers(s.managedMACHashers)
			}

			// run MAC tools
			allMacs := container.New()
			for _, tool := range s.macs {
				mac, err := tool.MAC(data, associatedData)
				if err != nil {
					return nil, fmt.Errorf("failed to calculate MAC with %s: %s", tool.Info().Name, err)
				}
				allMacs.Append(mac)
			}
			letter.Mac = allMacs.CompileData()
		}

	} else if len(s.ciphers) > 0 || len(s.integratedCiphers) > 0 || len(s.macs) > 0 {
		// check if there is really nothing to do with a key
		return nil, errors.New("missing a kdf tool")
	}

	// data processing is complete
	letter.Data = data

	// Signature
	if len(s.signers) > 0 {
		associatedSigningData := letter.compileAssociatedSigningData(associatedData)

		// run managed signing hashers
		if s.managedSigningHashers != nil {
			err = s.feedManagedHashers(s.managedSigningHashers, data, associatedSigningData)
			if err != nil {
				return nil, err
			}

			defer s.resetManagedHashers(s.managedSigningHashers)
		}

		// run signers
		for _, tool := range s.signers {
			//nolint:scopelint // function is executed immediately within loop
			err = s.envelope.LoopSenders(tool.Info().Name, func(signet *Signet) error {
				sig, err := tool.Sign(data, associatedSigningData, signet)
				if err != nil {
					return fmt.Errorf("failed to sign with %s: %s", tool.Info().Name, err)
				}

				letter.Signatures = append(letter.Signatures, &Seal{
					Scheme: tool.Info().Name,
					ID:     signet.ID,
					Value:  sig,
				})

				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}

	return letter, nil
}

// Open decrypts (and possibly verifies) the given letter and returns the original data. Storyline: Open takes a letter, checks any seals, opens it and returns the message.
func (s *Session) Open(letter *Letter) ([]byte, error) { //nolint:gocognit,gocyclo

	// debugging:
	/*
		fmt.Printf("opening: %+v\n", letter)
		for _, seal := range letter.Keys {
			fmt.Printf("key: %+v\n", seal)
		}
	*/

	var err error
	if s.wire == nil && letter.Version != 1 {
		return nil, fmt.Errorf("unsupported letter version: %d", letter.Version)
	}

	/////////
	// verify
	/////////

	// TODO: signature verification is run before tool setup. Currently, this is ok, but might change in the future. This might break additional signing algorithms that actually need setup.

	data := letter.Data

	// build associated data
	var associatedData []byte
	if len(s.integratedCiphers) > 0 || len(s.macs) > 0 {
		associatedData = letter.compileAssociatedData()
	}

	// Signature
	if len(s.signers) > 0 {
		associatedSigningData := letter.compileAssociatedSigningData(associatedData)

		// run managed signing hashers
		if s.managedSigningHashers != nil {
			err = s.feedManagedHashers(s.managedSigningHashers, data, associatedSigningData)
			if err != nil {
				return nil, err
			}

			defer s.resetManagedHashers(s.managedSigningHashers)
		}

		// run signers
		if len(s.envelope.Senders) != len(letter.Signatures) {
			return nil, errors.New("mismatch regarding available signatures and senders")
		}
		sigIndex := 0

		for _, tool := range s.signers {
			//nolint:scopelint // function is executed immediately within loop
			err = s.envelope.LoopSenders(tool.Info().Name, func(signet *Signet) error {
				err := tool.Verify(data, associatedSigningData, letter.Signatures[sigIndex].Value, signet)
				if err != nil {
					return fmt.Errorf("failed to verify signature (%s) with ID %s: %s", tool.Info().Name, letter.Signatures[sigIndex].ID, err)
				}

				sigIndex++
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}

	// end early if we are only verifying sigs
	if s.kdf == nil {
		// check if there is really nothing to do with a key
		if len(s.ciphers) > 0 || len(s.integratedCiphers) > 0 || len(s.macs) > 0 {
			return nil, errors.New("missing a kdf tool")
		}
		return data, nil
	}

	/////////////////
	// key management
	/////////////////

	// key establishment
	if s.wire != nil {
		err = s.wire.recvHandshakeAndInitKDF(letter)
		if err != nil {
			return nil, err
		}
	} else {
		keyMaterial, err := s.setupOpeningKeyMaterial(letter)
		if err != nil {
			return nil, err
		}

		// init KDF
		err = s.kdf.InitKeyDerivation(letter.Nonce, keyMaterial...)
		if err != nil {
			return nil, fmt.Errorf("failed to init %s kdf: %s", s.kdf.Info().Name, err)
		}
	}

	/////////////
	// decryption
	/////////////

	// setup tools
	err = s.setup()
	if err != nil {
		return nil, err
	}
	defer s.reset() //nolint:errcheck // TODO: handle error? Currently there should be none.

	// MAC
	if len(s.macs) > 0 {
		// run managed mac hashers
		if s.managedMACHashers != nil {
			err = s.feedManagedHashers(s.managedMACHashers, data, associatedData)
			if err != nil {
				return nil, err
			}

			defer s.resetManagedHashers(s.managedMACHashers)
		}

		// run MAC tools
		allMacs := container.New()
		for _, tool := range s.macs {
			mac, err := tool.MAC(data, associatedData)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate MAC with %s: %s", tool.Info().Name, err)
			}
			allMacs.Append(mac)
		}
		if subtle.ConstantTimeCompare(letter.Mac, allMacs.CompileData()) != 1 {
			return nil, fmt.Errorf("%w: MAC verification failed", ErrIntegrityViolation)
		}
	}

	// Integrated Ciphers / AEAD (in reversed order)
	for i := len(s.integratedCiphers) - 1; i >= 0; i-- {
		data, err = s.integratedCiphers[i].AuthenticatedDecrypt(data, associatedData)
		if err != nil {
			return nil, fmt.Errorf("%w: [%s] %s", ErrIntegrityViolation, s.integratedCiphers[i].Info().Name, err)
		}
	}

	// Ciphers (in reversed order)
	for i := len(s.ciphers) - 1; i >= 0; i-- {
		data, err = s.ciphers[i].Decrypt(data)
		if err != nil {
			return nil, fmt.Errorf("%w: decryption failed: [%s] %s", ErrIntegrityViolation, s.ciphers[i].Info().Name, err)
		}
	}

	return data, nil
}

// Verify verifies signatures of the given letter.
func (s *Session) Verify(letter *Letter) error {
	// debugging:
	/*
		fmt.Printf("opening: %+v\n", letter)
		for _, sig := range letter.Signatures {
			fmt.Printf("sig: %+v\n", sig)
		}
	*/

	var err error
	if s.wire == nil && letter.Version != 1 {
		return fmt.Errorf("unsupported letter version: %d", letter.Version)
	}

	/////////
	// verify
	/////////

	// TODO: signature verification is run before tool setup. Currently, this is ok, but might change in the future. This might break additional signing algorithms that actually need setup.

	data := letter.Data

	// build associated data
	var associatedData []byte
	if len(s.integratedCiphers) > 0 || len(s.macs) > 0 {
		associatedData = letter.compileAssociatedData()
	}

	// Signature
	if len(s.signers) > 0 {
		associatedSigningData := letter.compileAssociatedSigningData(associatedData)

		// run managed signing hashers
		if s.managedSigningHashers != nil {
			err = s.feedManagedHashers(s.managedSigningHashers, data, associatedSigningData)
			if err != nil {
				return err
			}

			defer s.resetManagedHashers(s.managedSigningHashers)
		}

		// run signers
		if len(s.envelope.Senders) != len(letter.Signatures) {
			return errors.New("mismatch regarding available signatures and senders")
		}
		sigIndex := 0

		for _, tool := range s.signers {
			//nolint:scopelint // function is executed immediately within loop
			err = s.envelope.LoopSenders(tool.Info().Name, func(signet *Signet) error {
				err := tool.Verify(data, associatedSigningData, letter.Signatures[sigIndex].Value, signet)
				if err != nil {
					return fmt.Errorf("failed to verify signature (%s) with ID %s: %s", tool.Info().Name, letter.Signatures[sigIndex].ID, err)
				}

				sigIndex++
				return nil
			})
			if err != nil {
				return err
			}
		}
	} else {
		return errors.New("no signatures to verify")
	}

	return nil
}

func (s *Session) setupClosingKeyMaterial(letter *Letter) ([][]byte, error) {
	signetsUsed := 0
	var keyMaterial [][]byte

	// add raw keys
	_ = s.envelope.LoopSecrets(SignetSchemeKey, func(signet *Signet) error {
		letter.Keys = append(letter.Keys, &Seal{
			Scheme: SignetSchemeKey,
			ID:     signet.ID,
		})

		keyMaterial = append(keyMaterial, signet.Key)
		signetsUsed++
		return nil
	})

	// add passwords
	err := s.envelope.LoopSecrets(SignetSchemePassword, func(signet *Signet) error {
		if len(signet.Key) == 0 {
			return fmt.Errorf("signet [%s] is missing it's password", signet.ID)
		}
		pwKey, err := s.passDerivator.DeriveKeyFromPassword(signet.Key, letter.Nonce)
		if err != nil {
			return fmt.Errorf("failed to get derive key from password with %s: %s", s.passDerivator.Info().Name, err)
		}
		letter.Keys = append(letter.Keys, &Seal{
			Scheme: SignetSchemePassword,
			ID:     signet.ID,
		})

		keyMaterial = append(keyMaterial, pwKey)
		signetsUsed++
		return nil
	})
	if err != nil {
		return nil, err
	}

	// add key exchange
	for _, tool := range s.keyExchangers {
		//nolint:scopelint // function is executed immediately within loop
		err = s.envelope.LoopRecipients(tool.Info().Name, func(recipient *Signet) error {
			// generate new sender exchange signet
			senderSignet := NewSignetBase(tool.Definition())
			err := senderSignet.GenerateKey()
			if err != nil {
				return fmt.Errorf("failed to generate new sender signet for %s: %s", tool.Info().Name, err)
			}

			// create exchange and add to letter
			exchKey, err := tool.MakeSharedKey(senderSignet, recipient)
			if err != nil {
				return fmt.Errorf("failed to make managed key with %s: %s", tool.Info().Name, err)
			}

			// add to letter
			senderRcpt, err := senderSignet.AsRecipient() // convert to public signet
			if err != nil {
				return fmt.Errorf("failed to get public sender signet for %s: %s", tool.Info().Name, err)
			}
			err = senderRcpt.StoreKey()
			if err != nil {
				return fmt.Errorf("failed to serialize sender public key for %s: %s", tool.Info().Name, err)
			}
			letter.Keys = append(letter.Keys, &Seal{
				ID:    recipient.ID,
				Value: senderRcpt.Key,
			})

			// save sender signet to state (or burn)
			if s.wire == nil {
				_ = senderSignet.Burn()
			} else {
				s.wire.eKXSignets = append(s.wire.eKXSignets, &kxPair{
					tool:   tool,
					signet: senderSignet,
				})
			}

			// add key
			keyMaterial = append(keyMaterial, exchKey)
			return nil
		})
	}
	if err != nil {
		return nil, err
	}

	// add key encapsulation
	for _, tool := range s.keyEncapsulators {
		//nolint:scopelint // function is executed immediately within loop
		err = s.envelope.LoopRecipients(tool.Info().Name, func(recipient *Signet) error {
			// save to state
			if s.wire != nil {
				s.wire.eKESignets = append(s.wire.eKESignets, &kePair{
					tool: tool,
				})
			}

			// generate new key
			newKey, err := RandomBytes(tool.Helper().DefaultSymmetricKeySize())
			if err != nil {
				return fmt.Errorf("failed to generate new key for %s: %s", tool.Info().Name, err)
			}

			// encapsulate key
			wrappedKey, err := tool.EncapsulateKey(newKey, recipient)
			if err != nil {
				return fmt.Errorf("failed to encapsulate key with %s: %s", tool.Info().Name, err)
			}

			// add to letter
			letter.Keys = append(letter.Keys, &Seal{
				ID:    recipient.ID,
				Value: wrappedKey,
			})

			// add key
			keyMaterial = append(keyMaterial, newKey)
			return nil
		})
	}
	if err != nil {
		return nil, err
	}

	return keyMaterial, nil
}

func (s *Session) setupOpeningKeyMaterial(letter *Letter) ([][]byte, error) {
	// Hint: Signets are loaded from the seals in the letter, so the order will always match.

	var keyMaterial [][]byte
	sealIndex := 0

	// sanity check
	if s.wire == nil {
		// TODO:
		// initial wire handshake is special:
		// key encapsulators send two seals in the initial handshake messages
		// one of them is added to the recipients
		// the other is a new ephermal key
		if len(s.envelope.Secrets)+
			len(s.envelope.Senders)+
			len(s.envelope.Recipients) < len(letter.Keys) {
			return nil, fmt.Errorf("missing Keys in letter")
		}
	}

	// add raw keys
	_ = s.envelope.LoopSecrets(SignetSchemeKey, func(signet *Signet) error {
		keyMaterial = append(keyMaterial, signet.Key)
		sealIndex++ // basically just skip, because key has to be loaded from the Signet anyway
		return nil
	})

	// add passwords
	err := s.envelope.LoopSecrets(SignetSchemePassword, func(signet *Signet) error {
		if len(signet.Key) == 0 {
			return fmt.Errorf("signet [%s] is missing it's password", signet.ID)
		}
		pwKey, err := s.passDerivator.DeriveKeyFromPassword(signet.Key, letter.Nonce)
		if err != nil {
			return fmt.Errorf("failed to get derive key from password with %s: %s", s.passDerivator.Info().Name, err)
		}

		keyMaterial = append(keyMaterial, pwKey)
		sealIndex++ // basically just skip, because password has to be loaded from the Signet anyway
		return nil
	})
	if err != nil {
		return nil, err
	}

	// add key exchange
	for _, tool := range s.keyExchangers {
		//nolint:scopelint // function is executed immediately within loop
		err = s.envelope.LoopRecipients(tool.Info().Name, func(signet *Signet) error {
			// get senderRcpt
			peerSignet := &Signet{
				Version: letter.Version,
				tool:    tool.Definition(),
				Key:     letter.Keys[sealIndex].Value,
				Public:  true,
			}
			sealIndex++
			// load key
			err := peerSignet.LoadKey()
			if err != nil {
				return fmt.Errorf("failed to load ephermal signet for key exchange: %s", err)
			}
			// save to state
			if s.wire != nil {
				s.wire.eKXSignets = append(s.wire.eKXSignets, &kxPair{
					tool: tool,
					peer: peerSignet,
				})
			}

			// make shared key
			exchKey, err := tool.MakeSharedKey(signet, peerSignet)
			if err != nil {
				return fmt.Errorf("failed to make shared key with %s: %s", tool.Info().Name, err)
			}

			// add key
			keyMaterial = append(keyMaterial, exchKey)
			return nil
		})
	}
	if err != nil {
		return nil, err
	}

	// add key encapsulation
	for _, tool := range s.keyEncapsulators {
		//nolint:scopelint // function is executed immediately within loop
		err = s.envelope.LoopRecipients(tool.Info().Name, func(signet *Signet) error {
			// save to state
			if s.wire != nil {
				s.wire.eKESignets = append(s.wire.eKESignets, &kePair{
					tool: tool,
				})
			}

			unwrappedKey, err := tool.UnwrapKey(letter.Keys[sealIndex].Value, signet)
			if err != nil {
				return err
			}
			sealIndex++

			// add key
			keyMaterial = append(keyMaterial, unwrappedKey)
			return nil
		})
	}
	if err != nil {
		return nil, err
	}

	return keyMaterial, nil
}

// setup runs the setup function on all tools.
func (s *Session) setup() error {
	for _, tool := range s.toolsWithState {
		err := tool.Setup()
		if err != nil {
			return fmt.Errorf("failed to run tool %s setup: %s", tool.Info().Name, err)
		}
	}

	return nil
}

// reset runs the reset function on all tools and managed hashers.
func (s *Session) reset() error {
	// reset all tools
	for _, tool := range s.toolsWithState {
		err := tool.Reset()
		if err != nil {
			return fmt.Errorf("failed to run tool %s reset: %s", tool.Info().Name, err)
		}
	}

	return nil
}

func (s *Session) feedManagedHashers(managedHashers map[string]*managedHasher, data, associatedData []byte) error {
	for _, mngdHasher := range managedHashers {
		n, err := mngdHasher.hash.Write(data)
		if err != nil {
			return fmt.Errorf("failed to write data to managed hasher %s: %s", mngdHasher.tool.Name, err)
		}
		if n != len(data) {
			return fmt.Errorf("failed to fully write data to managed hasher %s", mngdHasher.tool.Name)
		}

		n, err = mngdHasher.hash.Write(associatedData)
		if err != nil {
			return fmt.Errorf("failed to write associated data to managed hasher %s: %s", mngdHasher.tool.Name, err)
		}
		if n != len(associatedData) {
			return fmt.Errorf("failed to fully write associated data to managed hasher %s", mngdHasher.tool.Name)
		}
	}

	return nil
}

func (s *Session) resetManagedHashers(managedHashers map[string]*managedHasher) {
	for _, mngdHasher := range managedHashers {
		mngdHasher.hash.Reset()
	}
}
