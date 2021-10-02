package jess

import (
	"errors"
	"fmt"
)

// msgNo            uint64
// lastReKeyAtMsgNo uint64
//
// sendKeyCarryover []byte
// recvKeyCarryover []byte
//
// handshakeState uint8
// eKXSignetPairs [][2]*Signet
// eKESignets     []*Signet
// newKey  []byte

func (w *WireSession) sendHandshakeAndInitKDF(letter *Letter) error {
	var err error
	var keyMaterial [][]byte
	var burn bool

	// process handshake
	switch w.handshakeState {
	case wireStateInit: // client
		keyMaterial, err = w.session.setupClosingKeyMaterial(letter)
		if err != nil {
			return fmt.Errorf("failed to setup initial sending handshake key material: %w", err)
		}
		fallthrough

	case wireStateIdle: // client and server
		if w.msgNo == 0 || (!w.server && w.reKeyNeeded()) {
			err = w.generateLocalKeyExchangeSignets(letter)
			if err != nil {
				return fmt.Errorf("failed to generate local key exchange signets for initiating handshake: %w", err)
			}

			err = w.generateLocalKeyEncapsulationSignets(letter)
			if err != nil {
				return fmt.Errorf("failed to generate local key encapsulation signets for initiating handshake: %w", err)
			}

			w.handshakeState = wireStateAwaitKey
		}

	case wireStateSendKey: // server

		err = w.generateLocalKeyExchangeSignets(letter)
		if err != nil {
			return fmt.Errorf("failed to generate local key exchange signets for completing handshake: %w", err)
		}

		// debugging:
		/*
			fmt.Println("key states:")
			for _, kxPair := range w.eKXSignets {
				fmt.Printf("kxPair: %+v\n", kxPair)
				fmt.Printf("signet: %+v\n", kxPair.signet)
				fmt.Printf("peer: %+v\n", kxPair.peer)
			}
			for _, kePair := range w.eKESignets {
				fmt.Printf("kePair: %+v\n", kePair)
			}
		*/

		keyMaterial, err = w.makeSharedKeys(keyMaterial)
		if err != nil {
			return fmt.Errorf("failed to create shared keys for completing handshake: %w", err)
		}

		err = w.generateLocalKeyEncapsulationSignets(letter)
		if err != nil {
			return fmt.Errorf("failed to generate local key encapsulation signets for completing handshake: %w", err)
		}

		keyMaterial, err = w.makeAndEncapsulateNewKeys(letter, keyMaterial)
		if err != nil {
			return fmt.Errorf("failed to encapsulate keys for completing handshake: %w", err)
		}

		w.newKeyMaterial = copyKeyMaterial(keyMaterial)
		w.handshakeState = wireStatsAwaitApply

	case wireStateSendApply: // client
		keyMaterial = append(keyMaterial, w.newKeyMaterial...)
		letter.ApplyKeys = true
		burn = true
	}

	// add carryover key
	if w.msgNo == 0 {
		if w.session.DefaultSymmetricKeySize == 0 {
			return fmt.Errorf("missing default key size")
		}
		w.sendKeyCarryover = make([]byte, w.session.DefaultSymmetricKeySize)
	} else {
		keyMaterial = append(keyMaterial, w.sendKeyCarryover)
	}

	// init KDF
	err = w.session.kdf.InitKeyDerivation(letter.Nonce, keyMaterial...)
	if err != nil {
		return fmt.Errorf("failed to init %s kdf: %w", w.session.kdf.Info().Name, err)
	}

	// derive new carryover key
	err = w.session.kdf.DeriveKeyWriteTo(w.sendKeyCarryover)
	if err != nil {
		return fmt.Errorf("failed to iterate session key with %s: %w", w.session.kdf.Info().Name, err)
	}
	if w.msgNo == 0 {
		// copy initial sendkey to recvkey
		w.recvKeyCarryover = make([]byte, len(w.sendKeyCarryover))
		copy(w.recvKeyCarryover, w.sendKeyCarryover)
	}

	// increase msg counter
	w.msgNo++

	// burn and return
	if burn {
		return w.burnEphemeralKeys()
	}
	return nil
}

//nolint:gocognit
func (w *WireSession) recvHandshakeAndInitKDF(letter *Letter) error {
	var err error
	var keyMaterial [][]byte
	var burn bool

	// process handshake
	switch w.handshakeState {
	case wireStateInit: // server
		keyMaterial, err = w.session.setupOpeningKeyMaterial(letter)
		if err != nil {
			return fmt.Errorf("failed to setup initial receiving handshake key material: %w", err)
		}
		fallthrough

	case wireStateIdle: // server
		if len(letter.Keys) > 0 {
			// apply keys to pairs

			// check if there are the right amount of keys
			if len(w.session.keyEncapsulators) == 0 {
				// TODO:
				// initial wire handshake is special:
				// key encapsulators send two seals in the initial handshake messages
				// one of them is added to the recipients
				// the other is a new ephermal key
				if len(letter.Keys) != len(w.eKXSignets)+len(w.eKESignets) {
					return errors.New("failed to setup initial receiving handshake: incorrect amount of keys in letter")
				}
			}

			// assign keys to kx/ke pairs
			keyIndex := 0
			for _, kxPair := range w.eKXSignets {
				kxPair.peer = &Signet{
					Version: letter.Version,
					Key:     letter.Keys[keyIndex].Value,
					Public:  true,
					tool:    kxPair.tool.Definition(),
				}
				keyIndex++
			}
			for _, kePair := range w.eKESignets {
				// skip keys with ID
				for letter.Keys[keyIndex].ID != "" {
					keyIndex++
				}
				kePair.signet = &Signet{
					Version: letter.Version,
					Key:     letter.Keys[keyIndex].Value,
					Public:  true,
					tool:    kePair.tool.Definition(),
				}
				keyIndex++
			}

			w.handshakeState = wireStateSendKey
		}

	case wireStateAwaitKey: // client
		if len(letter.Keys) > 0 {
			// apply keys to pairs

			// check if there are the right amount of keys
			if len(letter.Keys) != len(w.eKXSignets)+len(w.eKESignets) {
				return errors.New("incorrect amount of keys in letter")
			}

			// assign keys to kx/ke pairs
			keyIndex := 0
			for _, kxPair := range w.eKXSignets {
				kxPair.peer = &Signet{
					Version: letter.Version,
					Key:     letter.Keys[keyIndex].Value,
					Public:  true,
					tool:    kxPair.tool.Definition(),
				}
				keyIndex++
			}
			for _, kePair := range w.eKESignets {
				kePair.seal = letter.Keys[keyIndex]
				keyIndex++
			}

			// make shared keys
			keyMaterial, err = w.makeSharedKeys(keyMaterial)
			if err != nil {
				return err
			}

			// unwrap keys
			keyMaterial, err = w.unwrapKeys(keyMaterial)
			if err != nil {
				return err
			}

			w.newKeyMaterial = copyKeyMaterial(keyMaterial)
			w.handshakeState = wireStateSendApply
		}

	case wireStatsAwaitApply: // server
		if letter.ApplyKeys {
			keyMaterial = append(keyMaterial, w.newKeyMaterial...)
			burn = true
		}
	}

	// add carryover key
	if w.msgNo == 0 {
		if w.session.DefaultSymmetricKeySize == 0 {
			return fmt.Errorf("missing default key size")
		}
		w.recvKeyCarryover = make([]byte, w.session.DefaultSymmetricKeySize)
	} else {
		keyMaterial = append(keyMaterial, w.recvKeyCarryover)
	}

	// init KDF
	err = w.session.kdf.InitKeyDerivation(letter.Nonce, keyMaterial...)
	if err != nil {
		return fmt.Errorf("failed to init %s kdf: %w", w.session.kdf.Info().Name, err)
	}

	// derive new carryover key
	err = w.session.kdf.DeriveKeyWriteTo(w.recvKeyCarryover)
	if err != nil {
		return fmt.Errorf("failed to iterate session key with %s: %w", w.session.kdf.Info().Name, err)
	}
	if w.msgNo == 0 {
		// copy initial recvkey to sendkey
		w.sendKeyCarryover = make([]byte, len(w.recvKeyCarryover))
		copy(w.sendKeyCarryover, w.recvKeyCarryover)
	}

	// increase msg counter
	w.msgNo++

	// burn and return
	if burn {
		return w.burnEphemeralKeys()
	}
	return nil
}

func (w *WireSession) generateLocalKeyExchangeSignets(letter *Letter) (err error) {
	for _, kxp := range w.eKXSignets {
		if kxp.signet == nil {
			// generate signet
			kxp.signet = NewSignetBase(kxp.tool.Definition())
			err := kxp.signet.GenerateKey()
			if err != nil {
				return err
			}
			// store signet
			err = kxp.signet.StoreKey()
			if err != nil {
				return err
			}

			// add to letter
			rcpt, err := kxp.signet.AsRecipient() // convert to public signet
			if err != nil {
				return err
			}
			err = rcpt.StoreKey()
			if err != nil {
				return err
			}
			letter.Keys = append(letter.Keys, &Seal{
				Value: rcpt.Key,
			})
		}
	}
	return nil
}

func (w *WireSession) makeSharedKeys(keyMaterial [][]byte) ([][]byte, error) {
	for _, kxp := range w.eKXSignets {
		// check signet
		if kxp.signet == nil {
			return nil, fmt.Errorf("missing key exchange signet for %s", kxp.tool.Info().Name)
		}
		// check peer signet
		if kxp.peer == nil {
			return nil, fmt.Errorf("missing key exchange recipient/peer for %s", kxp.tool.Info().Name)
		}

		// load peer key
		err := kxp.peer.LoadKey()
		if err != nil {
			return nil, err
		}

		// make shared key
		sharedKey, err := kxp.tool.MakeSharedKey(kxp.signet, kxp.peer)
		if err != nil {
			return nil, err
		}

		// append key to material
		keyMaterial = append(keyMaterial, sharedKey)
	}
	return keyMaterial, nil
}

func (w *WireSession) generateLocalKeyEncapsulationSignets(letter *Letter) (err error) {
	for _, kep := range w.eKESignets {
		if kep.signet == nil {
			// generate signet
			kep.signet = NewSignetBase(kep.tool.Definition())
			err := kep.signet.GenerateKey()
			if err != nil {
				return err
			}
			// store signet
			err = kep.signet.StoreKey()
			if err != nil {
				return err
			}

			// add to letter
			rcpt, err := kep.signet.AsRecipient() // convert to public signet
			if err != nil {
				return err
			}
			err = rcpt.StoreKey()
			if err != nil {
				return err
			}
			letter.Keys = append(letter.Keys, &Seal{
				Value: rcpt.Key,
			})
		}
	}
	return nil
}

func (w *WireSession) makeAndEncapsulateNewKeys(letter *Letter, keyMaterial [][]byte) ([][]byte, error) {
	for _, kep := range w.eKESignets {
		// check signet
		if kep.signet == nil {
			return nil, fmt.Errorf("missing key encapsulation signet for %s", kep.tool.Info().Name)
		}

		// load signet key
		err := kep.signet.LoadKey()
		if err != nil {
			return nil, err
		}

		// generate new key
		newKey, err := RandomBytes(w.session.DefaultSymmetricKeySize)
		if err != nil {
			return nil, err
		}

		// encapsulate it
		encapsulatedKey, err := kep.tool.EncapsulateKey(newKey, kep.signet)
		if err != nil {
			return nil, err
		}

		// add key to material and letter
		keyMaterial = append(keyMaterial, newKey)
		letter.Keys = append(letter.Keys, &Seal{Value: encapsulatedKey})
	}
	return keyMaterial, nil
}

func (w *WireSession) unwrapKeys(keyMaterial [][]byte) ([][]byte, error) {
	for _, kep := range w.eKESignets {
		// check signet
		if kep.signet == nil {
			return nil, fmt.Errorf("missing key encapsulation signet for %s", kep.tool.Info().Name)
		}
		// check seal
		if kep.seal == nil {
			return nil, fmt.Errorf("missing key encapsulation seal for %s", kep.tool.Info().Name)
		}

		// unwrap key
		unwrappedKey, err := kep.tool.UnwrapKey(kep.seal.Value, kep.signet)
		if err != nil {
			return nil, err
		}

		// add key to material
		keyMaterial = append(keyMaterial, unwrappedKey)
	}
	return keyMaterial, nil
}

// burnEphemeralKeys burns all the ephemeral key material in the session. This is currently ineffective, see known issues in the project's README.
func (w *WireSession) burnEphemeralKeys() error {
	var lastErr error

	// burn key exchange signets
	for _, entry := range w.eKXSignets {
		if entry.signet != nil {
			lastErr = entry.signet.Burn()
		}
		entry.signet = nil
		if entry.peer != nil {
			lastErr = entry.peer.Burn()
		}
		entry.peer = nil
	}

	// burn key encapsulation signets
	for _, entry := range w.eKESignets {
		if entry.signet != nil {
			lastErr = entry.signet.Burn()
		}
		entry.signet = nil
		if entry.seal != nil {
			Burn(entry.seal.Value)
		}
		entry.seal = nil
	}

	// burn new key material
	for _, part := range w.newKeyMaterial {
		Burn(part)
	}
	w.newKeyMaterial = nil

	return lastErr
}

func copyKeyMaterial(keyMaterial [][]byte) [][]byte {
	copied := make([][]byte, len(keyMaterial))
	for index, part := range keyMaterial {
		copiedPart := make([]byte, len(part))
		copy(copiedPart, part)
		copied[index] = copiedPart
	}
	return copied
}
