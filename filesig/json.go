package filesig

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
	"github.com/tidwall/sjson"
	"golang.org/x/exp/slices"

	"github.com/safing/jess"
	"github.com/safing/jess/lhash"
	"github.com/safing/structures/dsd"
)

// JSON file metadata keys.
const (
	JSONKeyPrefix    = "_jess-"
	JSONChecksumKey  = JSONKeyPrefix + "checksum"
	JSONSignatureKey = JSONKeyPrefix + "signature"
)

// AddJSONChecksum adds a checksum to a text file.
func AddJSONChecksum(data []byte) ([]byte, error) {
	// Extract content and metadata from json.
	content, checksums, signatures, err := jsonSplit(data)
	if err != nil {
		return nil, err
	}

	// Calculate checksum.
	h := lhash.BLAKE2b_256.Digest(content)
	checksums = append(checksums, h.Base58())

	// Sort and deduplicate checksums and sigs.
	slices.Sort(checksums)
	checksums = slices.Compact(checksums)
	slices.Sort(signatures)
	signatures = slices.Compact(signatures)

	// Add metadata and return.
	return jsonAddMeta(content, checksums, signatures)
}

// VerifyJSONChecksum checks a checksum in a text file.
func VerifyJSONChecksum(data []byte) error {
	// Extract content and metadata from json.
	content, checksums, _, err := jsonSplit(data)
	if err != nil {
		return err
	}

	// Verify all checksums.
	var checksumsVerified int
	for _, checksum := range checksums {
		// Parse checksum.
		h, err := lhash.FromBase58(checksum)
		if err != nil {
			return fmt.Errorf("%w: failed to parse labeled hash: %w", ErrChecksumFailed, err)
		}
		// Verify checksum.
		if !h.Matches(content) {
			return ErrChecksumFailed
		}
		checksumsVerified++
	}

	// Fail when no checksums were verified.
	if checksumsVerified == 0 {
		return ErrChecksumMissing
	}

	return nil
}

func AddJSONSignature(data []byte, envelope *jess.Envelope, trustStore jess.TrustStore) (signedData []byte, err error) {
	// Create session.
	session, err := envelope.Correspondence(trustStore)
	if err != nil {
		return nil, fmt.Errorf("invalid signing envelope: %w", err)
	}

	// Check if the envelope is suitable for signing.
	if err := envelope.Suite().Provides.CheckComplianceTo(fileSigRequirements); err != nil {
		return nil, fmt.Errorf("envelope not suitable for signing: %w", err)
	}

	// Extract content and metadata from json.
	content, checksums, signatures, err := jsonSplit(data)
	if err != nil {
		return nil, fmt.Errorf("invalid json structure: %w", err)
	}

	// Sign data.
	letter, err := session.Close(content)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Serialize signature and add it.
	letter.Data = nil
	sig, err := letter.ToDSD(dsd.CBOR)
	if err != nil {
		return nil, fmt.Errorf("serialize sig: %w", err)
	}
	signatures = append(signatures, base64.RawURLEncoding.EncodeToString(sig))

	// Sort and deduplicate checksums and sigs.
	slices.Sort(checksums)
	checksums = slices.Compact(checksums)
	slices.Sort(signatures)
	signatures = slices.Compact(signatures)

	// Add metadata and return.
	return jsonAddMeta(data, checksums, signatures)
}

func VerifyJSONSignature(data []byte, trustStore jess.TrustStore) (err error) {
	// Extract content and metadata from json.
	content, _, signatures, err := jsonSplit(data)
	if err != nil {
		return fmt.Errorf("invalid json structure: %w", err)
	}

	var signaturesVerified int
	for i, sig := range signatures {
		// Deserialize signature.
		sigData, err := base64.RawURLEncoding.DecodeString(sig)
		if err != nil {
			return fmt.Errorf("signature %d malformed: %w", i+1, err)
		}
		letter := &jess.Letter{}
		_, err = dsd.Load(sigData, letter)
		if err != nil {
			return fmt.Errorf("signature %d malformed: %w", i+1, err)
		}

		// Verify signature.
		letter.Data = content
		err = letter.Verify(fileSigRequirements, trustStore)
		if err != nil {
			return fmt.Errorf("signature %d invalid: %w", i+1, err)
		}

		signaturesVerified++
	}

	// Fail when no signatures were verified.
	if signaturesVerified == 0 {
		return ErrSignatureMissing
	}

	return nil
}

func jsonSplit(data []byte) (
	content []byte,
	checksums []string,
	signatures []string,
	err error,
) {
	// Check json.
	if !gjson.ValidBytes(data) {
		return nil, nil, nil, errors.New("invalid json")
	}
	content = data

	// Get checksums.
	result := gjson.GetBytes(content, JSONChecksumKey)
	if result.Exists() {
		if result.IsArray() {
			array := result.Array()
			checksums = make([]string, 0, len(array))
			for _, result := range array {
				if result.Type == gjson.String {
					checksums = append(checksums, result.String())
				}
			}
		} else if result.Type == gjson.String {
			checksums = []string{result.String()}
		}

		// Delete key.
		content, err = sjson.DeleteBytes(content, JSONChecksumKey)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Get signatures.
	result = gjson.GetBytes(content, JSONSignatureKey)
	if result.Exists() {
		if result.IsArray() {
			array := result.Array()
			signatures = make([]string, 0, len(array))
			for _, result := range array {
				if result.Type == gjson.String {
					signatures = append(signatures, result.String())
				}
			}
		} else if result.Type == gjson.String {
			signatures = []string{result.String()}
		}

		// Delete key.
		content, err = sjson.DeleteBytes(content, JSONSignatureKey)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Format for reproducible checksums and signatures.
	content = pretty.PrettyOptions(content, &pretty.Options{
		Width:    200,  // Must not change!
		Prefix:   "",   // Must not change!
		Indent:   " ",  // Must not change!
		SortKeys: true, // Must not change!
	})

	return content, checksums, signatures, nil
}

func jsonAddMeta(data []byte, checksums, signatures []string) ([]byte, error) {
	var (
		err  error
		opts = &sjson.Options{
			ReplaceInPlace: true,
		}
	)

	// Add checksums.
	switch len(checksums) {
	case 0:
		// Skip
	case 1:
		// Add single checksum.
		data, err = sjson.SetBytesOptions(
			data, JSONChecksumKey, checksums[0], opts,
		)
	default:
		// Add multiple checksums.
		data, err = sjson.SetBytesOptions(
			data, JSONChecksumKey, checksums, opts,
		)
	}
	if err != nil {
		return nil, err
	}

	// Add signatures.
	switch len(signatures) {
	case 0:
		// Skip
	case 1:
		// Add single signature.
		data, err = sjson.SetBytesOptions(
			data, JSONSignatureKey, signatures[0], opts,
		)
	default:
		// Add multiple signatures.
		data, err = sjson.SetBytesOptions(
			data, JSONSignatureKey, signatures, opts,
		)
	}
	if err != nil {
		return nil, err
	}

	// Final pretty print.
	data = pretty.PrettyOptions(data, &pretty.Options{
		Width:  200, // Must not change!
		Prefix: "",  // Must not change!
		Indent: " ", // Must not change!
	})

	return data, nil
}
