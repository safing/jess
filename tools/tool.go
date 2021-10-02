package tools

import "strings"

// Tool describes a cryptographic tool and is split into information and logic parts.
type Tool struct {
	// Info is a globally shared instance of generic tool information.
	Info *ToolInfo

	// StaticLogic holds a static (and possibly even nil) value of the tool logic in order to access certain handling methods.
	StaticLogic ToolLogic

	// Factory returns an initialized (but not yet set up) instance of ToolLogic.
	// Setup is done after initialization by overriding Setup().
	Factory func() ToolLogic
}

// ToolInfo holds generic information about a tool.
type ToolInfo struct {
	Name string

	Purpose uint8
	Options []uint8

	KeySize       int // in bytes
	NonceSize     int // in bytes
	SecurityLevel int // approx. attack complexity as 2^n

	Comment string
	Author  string
}

// Tool Purposes.
const (
	// Key Management and Creation, as well as Authenticity.

	// PurposeKeyDerivation declares key derivation capabilities.
	PurposeKeyDerivation uint8 = iota + 1

	// PurposePassDerivation declares password derivation capabilties (make a secure key out of a password).
	// Provides SenderAuthentication, ReceiverAuthentication requirements.
	PurposePassDerivation

	// PurposeKeyExchange declares (DH-style) key exchange capabilities.
	// A trusted key of the receiver must be supplied.
	// Provides ReceiverAuthentication attribute.
	PurposeKeyExchange

	// PurposeKeyEncapsulation declares key encapsulation capabilities (key is encrypted with the receivers public key)
	// A trusted key of the receiver must be supplied.
	// Provides ReceiverAuthentication attribute.
	PurposeKeyEncapsulation

	// PurposeSigning declares signing capabilities.
	// The receiver must already have the public key.
	// Provides SenderAuthentication attribute. Theoretically also provides integrity, but as signing is done after everything else, it will not be able to detect a wrong key during decryption.
	PurposeSigning

	// Confidentiality and Integrity.

	// PurposeIntegratedCipher declares that the tool provides both encryption and integrity verification capabilities.
	// Provies Confidentiality and Integrity requirements.
	PurposeIntegratedCipher

	// PurposeCipher declares that the tool provides encryption capabilities.
	// Provies Confidentiality attribute.
	PurposeCipher

	// PurposeMAC declares that the tool provides integrity verification capabilities.
	// Provies Integrity attribute.
	PurposeMAC
)

// Tool Options.
const (
	// Operation Types.

	// OptionStreaming declares that the tool can work with streaming data and might be given a io.Reader and io.Writer instead of just a []byte slice.
	// TODO: Implementation pending.
	OptionStreaming uint8 = iota + 1

	// Needs.

	// OptionNeedsManagedHasher declares that the tool requires a hashing algorithm to work. It will automatically hash everything that needs to be authenticated and may be shared with other algorithms.
	OptionNeedsManagedHasher

	// OptionNeedsDedicatedHasher declares that the tool requires a hashing algorithm to work. It will get its own instance and will have to do all the work itself.
	OptionNeedsDedicatedHasher

	// OptionNeedsSecurityLevel declares that the tool requires a specified security level. This will be derived from the rest of the used tools, or must be specified by the user directly.
	OptionNeedsSecurityLevel

	// OptionNeedsDefaultKeySize declares that the tool requires a default key size for operation. This will be derived from the rest of the used tools, or must be specified by the user directly.
	OptionNeedsDefaultKeySize

	// OptionHasState declares that the tool has an internal state and requires the setup and reset routines to be run before/after usage. KeyDerivation tools do not have to declare this, their state is handled separately.
	OptionHasState
)

// HasOption returns whether the *ToolInfo has the given option.
func (ti *ToolInfo) HasOption(option uint8) bool {
	for _, optionEntry := range ti.Options {
		if option == optionEntry {
			return true
		}
	}
	return false
}

// With uses the original ToolInfo as a template for a new ToolInfo and returns the new ToolInfo.
func (ti *ToolInfo) With(changes *ToolInfo) *ToolInfo {
	if changes.Name == "" {
		changes.Name = ti.Name
	}
	if changes.Purpose == 0 {
		changes.Purpose = ti.Purpose
	}
	if len(changes.Options) == 0 {
		changes.Options = ti.Options
	}
	if changes.KeySize == 0 {
		changes.KeySize = ti.KeySize
	}
	if changes.NonceSize == 0 {
		changes.NonceSize = ti.NonceSize
	}
	if changes.SecurityLevel == 0 {
		changes.SecurityLevel = ti.SecurityLevel
	}
	if changes.Comment == "" {
		changes.Comment = ti.Comment
	}
	if changes.Author == "" {
		changes.Author = ti.Author
	}

	return changes
}

// FormatPurpose returns the name of the declared purpose.
func (ti *ToolInfo) FormatPurpose() string {
	switch ti.Purpose {
	case PurposeKeyDerivation:
		return "KeyDerivation"
	case PurposePassDerivation:
		return "PassDerivation"
	case PurposeKeyExchange:
		return "KeyExchange"
	case PurposeKeyEncapsulation:
		return "KeyEncapsulation"
	case PurposeSigning:
		return "Signing"
	case PurposeIntegratedCipher:
		return "IntegratedCipher"
	case PurposeCipher:
		return "Cipher"
	case PurposeMAC:
		return "MAC"
	default:
		return "UNKNOWN"
	}
}

// FormatOptions returns a list of names of the declared options.
func (ti *ToolInfo) FormatOptions() string {
	if len(ti.Options) == 0 {
		return ""
	}

	var s []string
	for _, optionID := range ti.Options {
		switch optionID {
		case OptionStreaming:
			s = append(s, "Streaming")
		case OptionNeedsManagedHasher:
			s = append(s, "NeedsManagedHasher")
		case OptionNeedsDedicatedHasher:
			s = append(s, "NeedsDedicatedHasher")
		case OptionNeedsSecurityLevel:
			s = append(s, "NeedsSecurityLevel")
		case OptionNeedsDefaultKeySize:
			s = append(s, "NeedsDefaultKeySize")
		case OptionHasState:
			s = append(s, "HasState")
		default:
			s = append(s, "UNKNOWN")
		}
	}
	return strings.Join(s, ", ")
}
