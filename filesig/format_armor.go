package filesig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/safing/jess"
	"github.com/safing/portbase/formats/dsd"
)

const (
	sigFileArmorStart = "-----BEGIN JESS SIGNATURE-----"
	sigFileArmorEnd   = "-----END JESS SIGNATURE-----"
	sigFileLineLength = 64
)

var (
	sigFileArmorFindMatcher   = regexp.MustCompile(`(?ms)` + sigFileArmorStart + `(.+?)` + sigFileArmorEnd)
	sigFileArmorRemoveMatcher = regexp.MustCompile(`(?ms)` + sigFileArmorStart + `.+?` + sigFileArmorEnd + `\r?\n?`)
	whitespaceMatcher         = regexp.MustCompile(`(?ms)\s`)
)

// ParseSigFile parses a signature file and extracts any jess signatures from it.
// If signatures are returned along with an error, the error should be treated
// as a warning, but the result should also not be treated as a full success,
// as there might be missing signatures.
func ParseSigFile(fileData []byte) (signatures []*jess.Letter, err error) {
	var warning error
	captured := make([][]byte, 0, 1)

	// Find any signature blocks.
	matches := sigFileArmorFindMatcher.FindAllSubmatch(fileData, -1)
	for _, subMatches := range matches {
		if len(subMatches) >= 2 {
			// First entry is the whole match, second the submatch.
			captured = append(
				captured,
				bytes.TrimPrefix(
					bytes.TrimSuffix(
						whitespaceMatcher.ReplaceAll(subMatches[1], nil),
						[]byte(sigFileArmorEnd),
					),
					[]byte(sigFileArmorStart),
				),
			)
		}
	}

	// Parse any found signatures.
	signatures = make([]*jess.Letter, 0, len(captured))
	for _, sigBase64Data := range captured {
		// Decode from base64
		sigData := make([]byte, base64.RawStdEncoding.DecodedLen(len(sigBase64Data)))
		_, err = base64.RawStdEncoding.Decode(sigData, sigBase64Data)
		if err != nil {
			warning = err
			continue
		}

		// Parse signature.
		var letter *jess.Letter
		letter, err = jess.LetterFromDSD(sigData)
		if err != nil {
			warning = err
		} else {
			signatures = append(signatures, letter)
		}
	}

	return signatures, warning
}

// MakeSigFileSection creates a new section for a signature file.
func MakeSigFileSection(signature *jess.Letter) ([]byte, error) {
	// Serialize.
	data, err := signature.ToDSD(dsd.CBOR)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signature: %w", err)
	}

	// Encode to base64
	encodedData := make([]byte, base64.RawStdEncoding.EncodedLen(len(data)))
	base64.RawStdEncoding.Encode(encodedData, data)

	// Split into lines and add armor.
	splittedData := make([][]byte, 0, (len(encodedData)/sigFileLineLength)+3)
	splittedData = append(splittedData, []byte(sigFileArmorStart))
	for len(encodedData) > 0 {
		if len(encodedData) > sigFileLineLength {
			splittedData = append(splittedData, encodedData[:sigFileLineLength])
			encodedData = encodedData[sigFileLineLength:]
		} else {
			splittedData = append(splittedData, encodedData)
			encodedData = nil
		}
	}
	splittedData = append(splittedData, []byte(sigFileArmorEnd))
	linedData := bytes.Join(splittedData, []byte("\n"))

	return linedData, nil
}

// AddToSigFile adds the given signature to the signature file.
func AddToSigFile(signature *jess.Letter, sigFileData []byte, removeExistingJessSignatures bool) (newFileData []byte, err error) {
	// Create new section for new sig.
	newSigSection, err := MakeSigFileSection(signature)
	if err != nil {
		return nil, err
	}

	// Remove any existing jess signature sections.
	if removeExistingJessSignatures {
		sigFileData = sigFileArmorRemoveMatcher.ReplaceAll(sigFileData, nil)
	}

	// Append new signature section to end of file with a newline.
	sigFileData = append(sigFileData, []byte("\n")...)
	sigFileData = append(sigFileData, newSigSection...)

	return sigFileData, nil
}
