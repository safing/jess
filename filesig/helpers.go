package filesig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/safing/jess"
	"github.com/safing/jess/hashtools"
	"github.com/safing/jess/lhash"
)

// SignFile signs a file and replaces the signature file with a new one.
// If the dataFilePath is "-", the file data is read from stdin.
// Existing jess signatures in the signature file are removed.
func SignFile(dataFilePath, signatureFilePath string, metaData map[string]string, envelope *jess.Envelope, trustStore jess.TrustStore) (fileData *FileData, err error) {
	// Load encryption suite.
	if err := envelope.LoadSuite(); err != nil {
		return nil, err
	}

	// Extract the used hashing algorithm from the suite.
	var hashTool *hashtools.HashTool
	for _, toolID := range envelope.Suite().Tools {
		if strings.Contains(toolID, "(") {
			hashToolID := strings.Trim(strings.Split(toolID, "(")[1], "()")
			hashTool, _ = hashtools.Get(hashToolID)
			break
		}
	}
	if hashTool == nil {
		return nil, errors.New("suite not suitable for file signing")
	}

	// Hash the data file.
	var fileHash *lhash.LabeledHash
	if dataFilePath == "-" {
		fileHash, err = hashTool.LabeledHasher().DigestFromReader(os.Stdin)
	} else {
		fileHash, err = hashTool.LabeledHasher().DigestFile(dataFilePath)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	// Sign the file data.
	signature, fileData, err := SignFileData(fileHash, metaData, envelope, trustStore)
	if err != nil {
		return nil, fmt.Errorf("failed to sign file: %w", err)
	}

	sigFileData, err := os.ReadFile(signatureFilePath)
	var newSigFileData []byte
	switch {
	case err == nil:
		// Add signature to existing file.
		newSigFileData, err = AddToSigFile(signature, sigFileData, true)
		if err != nil {
			return nil, fmt.Errorf("failed to add signature to file: %w", err)
		}
	case errors.Is(err, fs.ErrNotExist):
		// Make signature section for saving to disk.
		newSigFileData, err = MakeSigFileSection(signature)
		if err != nil {
			return nil, fmt.Errorf("failed to format signature for file: %w", err)
		}
	default:
		return nil, fmt.Errorf("failed to open existing signature file: %w", err)
	}

	// Write the signature to file.
	if err := os.WriteFile(signatureFilePath, newSigFileData, 0o0644); err != nil { //nolint:gosec
		return nil, fmt.Errorf("failed to write signature to file: %w", err)
	}

	return fileData, nil
}

// VerifyFile verifies the given files and returns the verified file data.
// If the dataFilePath is "-", the file data is read from stdin.
// If an error is returned, there was an error in at least some part of the process.
// Any returned file data struct must be checked for an verification error.
func VerifyFile(dataFilePath, signatureFilePath string, metaData map[string]string, trustStore jess.TrustStore) (verifiedFileData []*FileData, err error) {
	var lastErr error

	// Read signature from file.
	sigFileData, err := os.ReadFile(signatureFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	// Extract all signatures.
	sigs, err := ParseSigFile(sigFileData)
	switch {
	case len(sigs) == 0 && err != nil:
		return nil, fmt.Errorf("failed to parse signature file: %w", err)
	case len(sigs) == 0:
		return nil, errors.New("no signatures found in signature file")
	case err != nil:
		lastErr = fmt.Errorf("failed to parse signature file: %w", err)
	}

	// Verify all signatures.
	goodFileData := make([]*FileData, 0, len(sigs))
	var badFileData []*FileData
	for _, sigLetter := range sigs {
		// Verify signature.
		fileData, err := VerifyFileData(sigLetter, metaData, trustStore)
		if err != nil {
			lastErr = err
			if fileData != nil {
				fileData.verificationError = err
				badFileData = append(badFileData, fileData)
			}
			continue
		}

		// Hash the file.
		var fileHash *lhash.LabeledHash
		if dataFilePath == "-" {
			fileHash, err = fileData.FileHash().Algorithm().DigestFromReader(os.Stdin)
		} else {
			fileHash, err = fileData.FileHash().Algorithm().DigestFile(dataFilePath)
		}
		if err != nil {
			lastErr = err
			fileData.verificationError = err
			badFileData = append(badFileData, fileData)
			continue
		}

		// Check if the hash matches.
		if !fileData.FileHash().Equal(fileHash) {
			lastErr = errors.New("signature invalid: file was modified")
			fileData.verificationError = lastErr
			badFileData = append(badFileData, fileData)
			continue
		}

		// Add verified file data to list for return.
		goodFileData = append(goodFileData, fileData)
	}

	return append(goodFileData, badFileData...), lastErr
}
