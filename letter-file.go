package jess

import (
	"errors"

	"github.com/safing/portbase/formats/dsd"

	"github.com/safing/portbase/container"
)

/*
### File Format Version 1

- File Format Version: varint
- Header: Letter without Data as byte block
- Data: byte block
*/

var (
	// ErrIncompatibleFileFormatVersion is returned when an incompatible wire format is encountered.
	ErrIncompatibleFileFormatVersion = errors.New("incompatible file format version")
)

// ToFileFormat serializes the letter for storing it as a file.
func (letter *Letter) ToFileFormat() (*container.Container, error) {
	c := container.New()

	// File Format Version: varint
	c.AppendNumber(1)

	// split header and data
	letterData := letter.Data
	letter.Data = nil

	// Header: Letter without Data as byte block
	headerData, err := dsd.DumpIndent(letter, dsd.JSON, "\t")
	if err != nil {
		return nil, err
	}
	// add newline for better raw viewability
	headerData = append(headerData, byte('\n'))
	// add header
	c.AppendAsBlock(headerData)

	// Data: byte block
	c.AppendAsBlock(letterData)

	// put back together
	letter.Data = letterData

	return c, nil
}

// LetterFromFileFormat parses a letter stored as a file.
func LetterFromFileFormat(c *container.Container) (*Letter, error) {
	letter := &Letter{}

	// File Format Version: varint
	fileFormatVersion, err := c.GetNextN8()
	if err != nil {
		return nil, err
	}
	if fileFormatVersion != 1 {
		return nil, ErrIncompatibleFileFormatVersion
	}

	// Header: Letter without Data as byte block
	data, err := c.GetNextBlock()
	if err != nil {
		return nil, err
	}
	_, err = dsd.Load(data, letter)
	if err != nil {
		return nil, err
	}

	// Data: byte block
	letterData, err := c.GetNextBlock()
	if err != nil {
		return nil, err
	}
	letter.Data = letterData

	return letter, nil
}
