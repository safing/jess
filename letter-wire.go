package jess

import (
	"errors"

	"github.com/safing/structures/container"
)

/*
### Wire Format Version 1

- Wire Format Version: varint
- Flags: varint
	- 1: Setup Msg (includes Version and Tools)
	- 2: Sending Keys
	- 4: Apply Keys
- Version: varint (if Setup Msg)
- SuiteID: byte block (if Setup Msg)
- Keys:
	- Amount: varint
	- IDs/Values: byte blocks
- Nonce: byte block
- Data: byte block
- MAC: byte block
*/

// ErrIncompatibleWireFormatVersion is returned when an incompatible wire format is encountered.
var ErrIncompatibleWireFormatVersion = errors.New("incompatible wire format version")

// ToWire serializes to letter for sending it over a network connection.
func (letter *Letter) ToWire() (*container.Container, error) {
	c := container.New()

	// Wire Format Version: varint
	c.AppendNumber(1)

	// Flags: varint
	// 	 - 1: Setup Msg (includes Version and Tools)
	// 	 - 2: Sending Keys
	// 	 - 4: Apply Keys
	var flags uint64
	if letter.Version > 0 {
		flags |= 1
	}
	if len(letter.Keys) > 0 {
		flags |= 2
	}
	if letter.ApplyKeys {
		flags |= 4
	}
	c.AppendNumber(flags)

	if letter.Version > 0 {
		// Version: varint (if Setup Msg)
		c.AppendNumber(uint64(letter.Version))

		// SuiteID: byte block (if Setup Msg)
		c.AppendAsBlock([]byte(letter.SuiteID))
	}

	if len(letter.Keys) > 0 {
		// Keys:
		// 	 - Amount: varint
		// 	 - IDs/Values: byte blocks
		c.AppendInt(len(letter.Keys))
		for _, seal := range letter.Keys {
			c.AppendAsBlock([]byte(seal.ID))
			c.AppendAsBlock(seal.Value)
		}
	}

	// Nonce: byte block
	c.AppendAsBlock(letter.Nonce)

	// Data: byte block
	c.AppendAsBlock(letter.Data)

	// MAC: byte block
	c.AppendAsBlock(letter.Mac)

	// debugging:
	// fmt.Printf("%+v\n", c.CompileData())

	return c, nil
}

// LetterFromWireData is a relay to LetterFromWire to quickly fix import issues of godep.
//
// Deprecated: Please use LetterFromWire with a fresh container directly.
func LetterFromWireData(data []byte) (*Letter, error) {
	return LetterFromWire(container.New(data))
}

// LetterFromWire parses a letter sent over a network connection.
func LetterFromWire(c *container.Container) (*Letter, error) {
	letter := &Letter{}

	// Wire Format Version: varint
	wireFormatVersion, err := c.GetNextN8()
	if err != nil {
		return nil, err
	}
	if wireFormatVersion != 1 {
		return nil, ErrIncompatibleWireFormatVersion
	}

	// Flags: varint
	// 	 - 1: Setup Msg (includes Version and Tools)
	// 	 - 2: Sending Keys
	// 	 - 4: Apply Keys
	var (
		setupMsg    bool
		sendingKeys bool
	)
	flags, err := c.GetNextN64()
	if err != nil {
		return nil, err
	}
	if flags&1 > 0 {
		setupMsg = true
	}
	if flags&2 > 0 {
		sendingKeys = true
	}
	if flags&4 > 0 {
		letter.ApplyKeys = true
	}

	if setupMsg {
		// Version: varint (if Setup Msg)
		n, err := c.GetNextN8()
		if err != nil {
			return nil, err
		}
		letter.Version = n

		// SuiteID: byte block (if Setup Msg)
		suiteID, err := c.GetNextBlock()
		if err != nil {
			return nil, err
		}
		letter.SuiteID = string(suiteID)
	}

	if sendingKeys {
		// Keys:
		// 	 - Amount: varint
		// 	 - IDs/Values: byte blocks
		n, err := c.GetNextN8()
		if err != nil {
			return nil, err
		}
		letter.Keys = make([]*Seal, n)
		for i := 0; i < len(letter.Keys); i++ {
			signetID, err := c.GetNextBlock()
			if err != nil {
				return nil, err
			}
			sealValue, err := c.GetNextBlock()
			if err != nil {
				return nil, err
			}
			letter.Keys[i] = &Seal{
				ID:    string(signetID),
				Value: sealValue,
			}
		}
	}

	// Nonce: byte block
	letter.Nonce, err = c.GetNextBlock()
	if err != nil {
		return nil, err
	}

	// Data: byte block
	letter.Data, err = c.GetNextBlock()
	if err != nil {
		return nil, err
	}

	// MAC: byte block
	letter.Mac, err = c.GetNextBlock()
	if err != nil {
		return nil, err
	}

	return letter, nil
}
