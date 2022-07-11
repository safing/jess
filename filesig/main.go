package filesig

import (
	"fmt"
	"time"

	"github.com/safing/jess"
	"github.com/safing/jess/lhash"
	"github.com/safing/portbase/formats/dsd"
)

var fileSigRequirements = jess.NewRequirements().
	Remove(jess.RecipientAuthentication).
	Remove(jess.Confidentiality)

// FileData describes a file that is signed.
type FileData struct {
	LabeledHash []byte
	fileHash    *lhash.LabeledHash

	SignedAt time.Time
	MetaData map[string]string

	signature         *jess.Letter
	verificationError error
}

// FileHash returns the labeled hash of the file that was signed.
func (fd *FileData) FileHash() *lhash.LabeledHash {
	return fd.fileHash
}

// Signature returns the signature, if present.
func (fd *FileData) Signature() *jess.Letter {
	return fd.signature
}

// VerificationError returns the error encountered during verification.
func (fd *FileData) VerificationError() error {
	return fd.verificationError
}

// SignFileData signs the given file checksum and metadata.
func SignFileData(fileHash *lhash.LabeledHash, metaData map[string]string, envelope *jess.Envelope, trustStore jess.TrustStore) (letter *jess.Letter, fd *FileData, err error) {
	// Create session.
	session, err := envelope.Correspondence(trustStore)
	if err != nil {
		return nil, nil, err
	}

	// Check if the envelope is suitable for signing.
	if err := envelope.Suite().Provides.CheckComplianceTo(fileSigRequirements); err != nil {
		return nil, nil, fmt.Errorf("envelope not suitable for signing")
	}

	// Create struct and transform data into serializable format to be signed.
	fd = &FileData{
		SignedAt: time.Now().Truncate(time.Second),
		fileHash: fileHash,
		MetaData: metaData,
	}
	fd.LabeledHash = fd.fileHash.Bytes()

	// Serialize file signature.
	fileData, err := dsd.Dump(fd, dsd.MsgPack)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize file signature data: %w", err)
	}

	// Sign data.
	letter, err = session.Close(fileData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign: %w", err)
	}

	return letter, fd, nil
}

// VerifyFileData verifies the given signed file data and returns the file data.
// If an error is returned, there was an error in at least some part of the process.
// Any returned file data struct must be checked for an verification error.
func VerifyFileData(letter *jess.Letter, requiredMetaData map[string]string, trustStore jess.TrustStore) (fd *FileData, err error) {
	// Parse data.
	fd = &FileData{
		signature: letter,
	}
	_, err = dsd.Load(letter.Data, fd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file signature data: %w", err)
	}

	// Verify signature and get data.
	_, err = letter.Open(fileSigRequirements, trustStore)
	if err != nil {
		fd.verificationError = fmt.Errorf("failed to verify file signature: %w", err)
		return fd, fd.verificationError
	}

	// Check if the required metadata matches.
	for reqKey, reqValue := range requiredMetaData {
		sigMetaValue, ok := fd.MetaData[reqKey]
		if !ok {
			fd.verificationError = fmt.Errorf("missing required metadata key %q", reqKey)
			return fd, fd.verificationError
		}
		if sigMetaValue != reqValue {
			fd.verificationError = fmt.Errorf("required metadata %q=%q does not match the file's value %q", reqKey, reqValue, sigMetaValue)
			return fd, fd.verificationError
		}
	}

	// Parse labeled hash.
	fd.fileHash, err = lhash.Load(fd.LabeledHash)
	if err != nil {
		fd.verificationError = fmt.Errorf("failed to parse file checksum: %w", err)
		return fd, fd.verificationError
	}

	return fd, nil
}
