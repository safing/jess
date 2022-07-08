package jess

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/safing/jess"
	"github.com/safing/jess/hashtools"
)

// SignFile signs a file and replaces the signature file with a new one.
func SignFile(dataFilePath, signatureFilePath string, metaData map[string]string, envelope *jess.Envelope, trustStore jess.TrustStore) (fileData *FileData, err error) {
	// Load encryption suite.
	if err := envelope.LoadSuite(); err != nil {
		return nil, err
	}

	// Extract the used hashing algorithm from the suite.
	var hashTool *hashtools.HashTool
	for _, toolID := range envelope.Suite().Tools {
		if strings.Contains(toolID, "(") {
			hashToolID := strings.Trim(strings.Split(toolID, "(")[0], "()")
			hashTool, _ = hashtools.Get(hashToolID)
			break
		}
	}
	if hashTool == nil {
		return nil, errors.New("suite not suitable for file signing")
	}

	// Hash the data file.
	fileHash, err := hashTool.LabeledHasher().DigestFile(dataFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	// Sign the file data.
	signature, fileData, err := SignFileData(fileHash, metaData, envelope, trustStore)
	if err != nil {
		return nil, fmt.Errorf("failed to sign file: %w", err)
	}

	// Make signature section for saving to disk.
	signatureSection, err := MakeSigFileSection(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to format signature for file: %w", err)
	}

	// Write the signature to file.
	if err := ioutil.WriteFile(signatureFilePath, signatureSection, 0o0644); err != nil { //nolint:gosec
		return nil, fmt.Errorf("failed to write signature to file: %w", err)
	}

	return fileData, nil
}

// VerifyFile verifies the given files and returns the verified file data.
// If an error is returned, there was an error in at least some part of the process.
// Any returned file data struct must be checked for an verification error.
func VerifyFile(dataFilePath, signatureFilePath string, metaData map[string]string, trustStore jess.TrustStore) (verifiedFileData []*FileData, err error) {
	var lastErr error

	// Read signature from file.
	sigFileData, err := ioutil.ReadFile(signatureFilePath)
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
		fileHash, err := fileData.FileHash().Algorithm().DigestFile(dataFilePath)
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
