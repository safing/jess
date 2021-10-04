package tools

import (
	"errors"

	"github.com/safing/jess/hashtools"
)

// ToolLogic is the uniform interface for all tools.
type ToolLogic interface {
	// Init and Meta methods

	// Init is called by the internal tool initialized procedure and is called by New().  Do not override.
	Init(tool *Tool, helper HelperInt, hashTool *hashtools.HashTool, hashSumFn func() ([]byte, error))

	// Info returns information about the Tool. Init is only called once per ToolLogic instance. Do not override.
	Info() *ToolInfo
	// Definition returns Tool's definition. Do not override.
	Definition() *Tool
	// Factory returns a new instance of the ToolLogic. Do not override.
	Factory() ToolLogic
	// Helper returns a Helper. Do not override.
	Helper() HelperInt
	// HashTool returns the assigned HashTool. Do not override.
	HashTool() *hashtools.HashTool
	// ManagedHashSum returns the hashsum of the managed hasher. Must be enabled by the tool by declaring FeatureNeedsManagedHasher. Do not override.
	ManagedHashSum() ([]byte, error)

	// Setup is called after Init and can be used the tool to do some custom setup before being used. It is called before every use of the ToolLogic instance. Override at will.
	// If a Tool needs key material, it needs to be requested here.
	Setup() error

	// Reset is called after all operations have finished and should be used to do some cleanup, burn all key material and prepare for the next usage. It is called after every use of the ToolLogic instance. Override at will.
	Reset() error

	// Tool Logic Methods

	// Key Creation

	// DeriveKeyFromPassword takes a password and turns it into a key.
	// Must be overridden by tools that declare FeaturePassDerivation.
	DeriveKeyFromPassword(password []byte, salt []byte) ([]byte, error)

	// InitKeyDerivation initializes the key generation.
	// Must be overridden by tools that declare FeatureKeyDerivation.
	InitKeyDerivation(nonce []byte, material ...[]byte) error

	// DeriveKey derives a new key.
	// Must be overridden by tools that declare FeatureKeyDerivation.
	DeriveKey(size int) ([]byte, error)

	// DeriveKeyWriteTo derives a new key and writes it into the given slice.
	// Must be overridden by tools that declare FeatureKeyDerivation.
	DeriveKeyWriteTo(newKey []byte) error

	// Key Exchanging

	// MakeSharedKey takes a local private key and a remote public key and generates a shared secret.
	// Must be overridden by tools that declare FeatureKeyExchange.
	MakeSharedKey(local SignetInt, remote SignetInt) ([]byte, error)

	// EncapsulateKey wraps a key using the given Signet (remote public key).
	// Must be overridden by tools that declare FeatureKeyEncapsulation.
	EncapsulateKey(key []byte, remote SignetInt) ([]byte, error)

	// EncapsulateKey unwraps an encapsulated key using the given Signet (local private key).
	// Must be overridden by tools that declare FeatureKeyEncapsulation.
	UnwrapKey(wrappedKey []byte, local SignetInt) ([]byte, error)

	// Encryption and Authentication

	// Encrypt encrypts the given data.
	// Must be overridden by tools that declare FeatureCipher.
	Encrypt(data []byte) ([]byte, error)

	// Decrypt decrypts the given data.
	// Must be overridden by tools that declare FeatureCipher.
	Decrypt(data []byte) ([]byte, error)

	// Encrypt encrypts the given data, and authenticates both data and associatedData.
	// Must be overridden by tools that declare FeatureIntegratedCipher.
	AuthenticatedEncrypt(data, associatedData []byte) ([]byte, error)

	// Decrypt decrypts the given data, and authenticates both data and associatedData.
	// Must be overridden by tools that declare FeatureIntegratedCipher.
	AuthenticatedDecrypt(data, associatedData []byte) ([]byte, error)

	// MAC returns a message authentication code for the given data and associatedData. If the Tool uses a managed hasher, it will be ready for fetching the sum of both. In that case, no data has to be processed again.
	// Must be overridden by tools that declare FeatureMAC.
	MAC(data, associatedData []byte) ([]byte, error)

	// Signing

	// Sign signs the data with the given Signet (local private key).
	// Must be overridden by tools that declare FeatureSigning.
	Sign(data, associatedData []byte, local SignetInt) ([]byte, error)

	// Verify verifies the signature of the data using the given signature and Signet (remote public key).
	// Must be overridden by tools that declare FeatureSigning.
	Verify(data, associatedData, signature []byte, remote SignetInt) error

	// Signet Handling

	// LoadKey loads a key from the Signet's key storage (`Key`) into the Signet's cache (`Loaded*`). If the Signet is marked as public, the storage is expected to only have the public key present, only only it will be loaded.
	// Must work with a static (no Setup()) ToolLogic.
	// Must be overridden by tools that declare FeatureKeyExchange, FeatureKeyEncapsulation or FeatureSigning.
	LoadKey(SignetInt) error

	// StoreKey stores a loaded key from the Signet's cache (`Loaded*`) in the Signet's key storage (`Key`). If the Signet is marked as public, only the public key will be stored.
	// Must work with a static (no Setup()) ToolLogic.
	// Must be overridden by tools that declare FeatureKeyExchange, FeatureKeyEncapsulation or FeatureSigning.
	StoreKey(SignetInt) error

	// GenerateKey generates a new key pair and stores it in the given Signet. They key pair is not stored in the Signet's key storage (`Key`).
	// Must work with a static (no Setup()) ToolLogic.
	// Must be overridden by tools that declare FeatureKeyExchange, FeatureKeyEncapsulation or FeatureSigning.
	GenerateKey(signet SignetInt) error

	// BurnKey deletes the loaded keys in the Signet.
	// Must work with a static (no Setup()) ToolLogic.
	// Must be overridden by tools that declare FeatureKeyExchange, FeatureKeyEncapsulation or FeatureSigning.
	// Implementations of this are currently ineffective, see known issues in the project's README.
	BurnKey(signet SignetInt) error

	// SecurityLevel returns the security level (approximate attack complexity as 2^n) of the given tool.
	// May be overridden if needed for custom calculation (ie. based on actual key size in signet or hash tool). Init() will be called before SecurityLevel() is called.
	SecurityLevel(signet SignetInt) (int, error)
}

// ToolLogicBase covers all methods of the ToolLogic interface with dummy implementations to reduce boilerplate code.
type ToolLogicBase struct {
	tool      *Tool
	helper    HelperInt
	hashTool  *hashtools.HashTool
	hashSumFn func() ([]byte, error)
}

// Init is called by the internal tool initialized procedure and is called by NewTool().  Do not override.
func (tlb *ToolLogicBase) Init(tool *Tool, helper HelperInt, hashTool *hashtools.HashTool, hashSumFn func() ([]byte, error)) {
	tlb.tool = tool
	tlb.helper = helper
	tlb.hashTool = hashTool
	tlb.hashSumFn = hashSumFn
}

// Info returns information about the Tool. Do not override.
func (tlb *ToolLogicBase) Info() *ToolInfo {
	return tlb.tool.Info
}

// Definition returns Tool's definition. Do not override.
func (tlb *ToolLogicBase) Definition() *Tool {
	return tlb.tool
}

// Factory returns a new instance of the ToolLogic. Do not override.
func (tlb *ToolLogicBase) Factory() ToolLogic {
	return tlb.tool.Factory()
}

// Helper returns a Helper. Do not override.
func (tlb *ToolLogicBase) Helper() HelperInt {
	return tlb.helper
}

// HashTool returns the assigned HashTool. Do not override.
func (tlb *ToolLogicBase) HashTool() *hashtools.HashTool {
	return tlb.hashTool
}

// ManagedHashSum returns the hashsum of the managed hasher. Must be enabled by the tool by declaring FeatureNeedsManagedHasher. Do not override.
func (tlb *ToolLogicBase) ManagedHashSum() ([]byte, error) {
	if tlb.hashSumFn == nil {
		return nil, errors.New("managed hash not configured")
	}
	return tlb.hashSumFn()
}

// Setup is called after Init and can be used the tool to do some custom setup before being used. Override at will.
// If a Tool needs key material, it needs to be requested here.
func (tlb *ToolLogicBase) Setup() error {
	return nil
}

// Reset is called after all operations have finished and should be used to do cleanup and burn all key material. Override at will.
func (tlb *ToolLogicBase) Reset() error {
	return nil
}

// SecurityLevel returns the security level (approximate attack complexity as 2^n) of the given tool.
// May be overridden if needed for custom calculation (ie. based on actual key size in signet or hash tool). Init() will be called before SecurityLevel() is called.
func (tlb *ToolLogicBase) SecurityLevel(signet SignetInt) (int, error) {
	if tlb.hashTool != nil {
		// return the hashtool's security level, if tool does not have one
		if tlb.tool.Info.SecurityLevel == 0 {
			return tlb.hashTool.SecurityLevel, nil
		}
		// return the hashtool's security level, if it is lower than the tools' level
		if tlb.hashTool.SecurityLevel < tlb.tool.Info.SecurityLevel {
			return tlb.hashTool.SecurityLevel, nil
		}
	}
	return tlb.tool.Info.SecurityLevel, nil
}

// Compliance Dummy Methods

// DeriveKeyFromPassword implements the ToolLogic interface.
func (tlb *ToolLogicBase) DeriveKeyFromPassword(password []byte, salt []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// InitKeyDerivation implements the ToolLogic interface.
func (tlb *ToolLogicBase) InitKeyDerivation(nonce []byte, material ...[]byte) error {
	return ErrNotImplemented
}

// DeriveKey implements the ToolLogic interface.
func (tlb *ToolLogicBase) DeriveKey(size int) ([]byte, error) {
	return nil, ErrNotImplemented
}

// DeriveKeyWriteTo implements the ToolLogic interface.
func (tlb *ToolLogicBase) DeriveKeyWriteTo(newKey []byte) error {
	return ErrNotImplemented
}

// MakeSharedKey implements the ToolLogic interface.
func (tlb *ToolLogicBase) MakeSharedKey(local SignetInt, remote SignetInt) ([]byte, error) {
	return nil, ErrNotImplemented
}

// EncapsulateKey implements the ToolLogic interface.
func (tlb *ToolLogicBase) EncapsulateKey(key []byte, remote SignetInt) ([]byte, error) {
	return nil, ErrNotImplemented
}

// UnwrapKey implements the ToolLogic interface.
func (tlb *ToolLogicBase) UnwrapKey(wrappedKey []byte, local SignetInt) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Encrypt implements the ToolLogic interface.
func (tlb *ToolLogicBase) Encrypt(data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Decrypt implements the ToolLogic interface.
func (tlb *ToolLogicBase) Decrypt(data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// AuthenticatedEncrypt implements the ToolLogic interface.
func (tlb *ToolLogicBase) AuthenticatedEncrypt(data, associatedData []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// AuthenticatedDecrypt implements the ToolLogic interface.
func (tlb *ToolLogicBase) AuthenticatedDecrypt(data, associatedData []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// MAC implements the ToolLogic interface.
func (tlb *ToolLogicBase) MAC(data, associatedData []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Sign implements the ToolLogic interface.
func (tlb *ToolLogicBase) Sign(data, associatedData []byte, local SignetInt) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Verify implements the ToolLogic interface.
func (tlb *ToolLogicBase) Verify(data, associatedData, signature []byte, remote SignetInt) error {
	return ErrNotImplemented
}

// LoadKey implements the ToolLogic interface.
func (tlb *ToolLogicBase) LoadKey(SignetInt) error {
	return ErrNotImplemented
}

// StoreKey implements the ToolLogic interface.
func (tlb *ToolLogicBase) StoreKey(SignetInt) error {
	return ErrNotImplemented
}

// GenerateKey implements the ToolLogic interface.
func (tlb *ToolLogicBase) GenerateKey(signet SignetInt) error {
	return ErrNotImplemented
}

// BurnKey implements the ToolLogic interface. This is currently ineffective, see known issues in the project's README.
func (tlb *ToolLogicBase) BurnKey(signet SignetInt) error {
	return ErrNotImplemented
}
