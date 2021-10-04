package jess

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestSerialization(t *testing.T) {
	t.Parallel()

	subject := &Letter{
		Version: 1,
		SuiteID: SuiteComplete,
		Keys: []*Seal{
			{ID: "a"},
			{ID: "b"},
			{ID: "c"},
		},
		Nonce:     []byte{1, 2, 3},
		Data:      []byte{4, 5, 6},
		Mac:       []byte{7, 8, 9},
		ApplyKeys: true,
	}
	testSerialize(t, subject, true)

	subject.Version = 0
	subject.SuiteID = ""
	testSerialize(t, subject, true)

	subject.ApplyKeys = false
	testSerialize(t, subject, true)

	subject.Keys = nil
	testSerialize(t, subject, true)
}

func testSerialize(t *testing.T, letter *Letter, wireFormat bool) { //nolint:unparam
	t.Helper()

	// File Format

	fileData, err := letter.ToFileFormat()
	if err != nil {
		t.Error(err)
		return
	}

	letter2, err := LetterFromFileFormat(fileData)
	if err != nil {
		t.Error(err)
		return
	}

	err = letter.CheckEqual(letter2)
	if err != nil {
		t.Errorf("letters (file format) do not match: %s\n%+v\n%+v\n", err, jsonFormat(letter), jsonFormat(letter2))
		return
	}

	// Wire Format

	if !wireFormat {
		return
	}

	wire, err := letter.ToWire()
	if err != nil {
		t.Error(err)
		return
	}

	letter3, err := LetterFromWire(wire)
	if err != nil {
		t.Error(err)
		return
	}

	err = letter.CheckEqual(letter3)
	if err != nil {
		t.Errorf("letters (wire format) do not match: %s\n%+v\n%+v\n", err, jsonFormat(letter), jsonFormat(letter3))
		return
	}
}

func (letter *Letter) CheckEqual(other *Letter) error {
	letterValue := reflect.ValueOf(*letter)
	otherValue := reflect.ValueOf(*other)

	var ok bool
	numElements := letterValue.NumField()
	for i := 0; i < numElements; i++ {
		name := letterValue.Type().Field(i).Name
		switch name {
		case "Data": // TODO: this required special handling in the past, leave it here for now.
			ok = bytes.Equal(letter.Data, other.Data)
		default:
			ok = reflect.DeepEqual(letterValue.Field(i).Interface(), otherValue.Field(i).Interface())
		}

		if !ok {
			return fmt.Errorf("field %s mismatches", name)
		}
	}

	return nil
}

func jsonFormat(v interface{}) string {
	formatted, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("<JSON format error: %s>", err)
	}
	return string(formatted)
}
