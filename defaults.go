package jess

var (
	// must be var in order decrease for testing for better speed

	defaultSecurityLevel = 128
	minimumSecurityLevel = 0

	defaultSymmetricKeySize = 16
	minimumSymmetricKeySize = 0
)

// Currently recommended toolsets.
var (
	RecommendedNetwork         = []string{"ECDH-X25519", "HKDF(SHA2-256)", "CHACHA20-POLY1305"}
	RecommendedStoragePassword = []string{"PBKDF2-SHA2-256", "HKDF(SHA2-256)", "CHACHA20-POLY1305"}
	RecommendedStorageKey      = []string{"HKDF(SHA2-256)", "CHACHA20-POLY1305"}

	RecommendedStorageRecipient = []string{"ECDH-X25519", "HKDF(SHA2-256)", "CHACHA20-POLY1305"}

	RecommendedSigning = []string{"Ed25519(SHA2-256)"}
)

// SetMinimumSecurityLevel sets a global minimum security level. Jess will refuse any operations that violate this security level.
func SetMinimumSecurityLevel(securityLevel int) {
	defaultSecurityLevel = securityLevel
	minimumSecurityLevel = securityLevel
}

// SetDefaultKeySize sets a global default key size to be used as a fallback value. This will be only used if the default key size could not be derived from already present information.
func SetDefaultKeySize(sizeInBytes int) {
	defaultSymmetricKeySize = sizeInBytes
	minimumSymmetricKeySize = sizeInBytes
}
