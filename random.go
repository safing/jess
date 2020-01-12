package jess

import (
	"crypto/rand"
	"io"

	"github.com/tevino/abool"
)

var (
	customRandReader     io.Reader
	customRandReaderFlag = abool.NewBool(false)
)

// Random returns the io.Reader for reading randomness. By default, it uses crypto/rand.Reader.
func Random() io.Reader {
	if customRandReaderFlag.IsSet() {
		return customRandReader
	}
	return rand.Reader
}

// RandomBytes returns the specified amount of random bytes in a []byte slice. By default, it uses crypto/rand.Reader.
func RandomBytes(n int) ([]byte, error) {
	rBytes := make([]byte, n)

	bytesRead, err := Random().Read(rBytes)
	if err != nil {
		return nil, err
	}
	if bytesRead != n {
		return nil, ErrInsufficientRandom
	}

	return rBytes, nil
}

// SetCustomRNG sets a custom RNG to be used with jess.
func SetCustomRNG(randReader io.Reader) {
	if !customRandReaderFlag.IsSet() {
		customRandReader = randReader
		customRandReaderFlag.Set()
	}
}
