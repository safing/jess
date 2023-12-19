package jess //nolint:dupl

var (
	// SuiteKeyV2 is a cipher suite for encryption with a key.
	SuiteKeyV2 = registerSuite(&Suite{
		ID:            "key_v2",
		Tools:         []string{"BLAKE3-KDF", "CHACHA20-POLY1305"},
		Provides:      NewRequirements(),
		SecurityLevel: 128,
		Status:        SuiteStatusPermitted,
	})
	// SuitePasswordV2 is a cipher suite for encryption with a password.
	SuitePasswordV2 = registerSuite(&Suite{
		ID:            "pw_v2",
		Tools:         []string{"SCRYPT-20", "BLAKE3-KDF", "CHACHA20-POLY1305"},
		Provides:      NewRequirements(),
		SecurityLevel: 128,
		Status:        SuiteStatusPermitted,
	})
	// SuiteRcptOnlyV2 is a cipher suite for encrypting for someone, but without verifying the sender/source.
	SuiteRcptOnlyV2 = registerSuite(&Suite{
		ID:            "rcpt_v2",
		Tools:         []string{"ECDH-X25519", "BLAKE3-KDF", "CHACHA20-POLY1305"},
		Provides:      NewRequirements().Remove(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusPermitted,
	})
	// SuiteSignV2 is a cipher suite for signing (no encryption).
	SuiteSignV2 = registerSuite(&Suite{
		ID:            "sign_v2",
		Tools:         []string{"Ed25519(BLAKE3)"},
		Provides:      newEmptyRequirements().Add(Integrity).Add(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusPermitted,
	})
	// SuiteSignFileV2 is a cipher suite for signing files (no encryption).
	// SHA2_256 is chosen for better compatibility with other tool sets and workflows.
	SuiteSignFileV2 = registerSuite(&Suite{
		ID:            "signfile_v2",
		Tools:         []string{"Ed25519(BLAKE3)"},
		Provides:      newEmptyRequirements().Add(Integrity).Add(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusPermitted,
	})
	// SuiteCompleteV2 is a cipher suite for both encrypting for someone and signing.
	SuiteCompleteV2 = registerSuite(&Suite{
		ID:            "v2",
		Tools:         []string{"ECDH-X25519", "Ed25519(BLAKE3)", "BLAKE3-KDF", "CHACHA20-POLY1305"},
		Provides:      NewRequirements(),
		SecurityLevel: 128,
		Status:        SuiteStatusPermitted,
	})
	// SuiteWireV2 is a cipher suite for network communication, including authentication of the server, but not the client.
	SuiteWireV2 = registerSuite(&Suite{
		ID:            "w2",
		Tools:         []string{"ECDH-X25519", "BLAKE3-KDF", "CHACHA20-POLY1305"},
		Provides:      NewRequirements().Remove(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusPermitted,
	})
)
