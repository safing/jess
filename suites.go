package jess

var (
	// Suite Lists.
	suitesMap  = make(map[string]*Suite)
	suitesList []*Suite

	// Suite Definitions.

	// SuiteKeyV1 is a cipher suite for encryption with a key.
	SuiteKeyV1 = registerSuite(&Suite{
		ID:            "key_v1",
		Tools:         []string{"HKDF(BLAKE2b-256)", "CHACHA20-POLY1305"},
		Provides:      NewRequirements(),
		SecurityLevel: 128,
		Status:        SuiteStatusRecommended,
	})
	// SuitePasswordV1 is a cipher suite for encryption with a password.
	SuitePasswordV1 = registerSuite(&Suite{
		ID:            "pw_v1",
		Tools:         []string{"SCRYPT-20", "HKDF(BLAKE2b-256)", "CHACHA20-POLY1305"},
		Provides:      NewRequirements(),
		SecurityLevel: 128,
		Status:        SuiteStatusRecommended,
	})
	// SuiteRcptOnlyV1 is a cipher suite for encrypting for someone, but without verifying the sender/source.
	SuiteRcptOnlyV1 = registerSuite(&Suite{
		ID:            "rcpt_v1",
		Tools:         []string{"ECDH-X25519", "HKDF(BLAKE2b-256)", "CHACHA20-POLY1305"},
		Provides:      NewRequirements().Remove(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusRecommended,
	})
	// SuiteSignV1 is a cipher suite for signing (no encryption).
	SuiteSignV1 = registerSuite(&Suite{
		ID:            "sign_v1",
		Tools:         []string{"Ed25519(BLAKE2b-256)"},
		Provides:      newEmptyRequirements().Add(Integrity).Add(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusRecommended,
	})
	// SuiteSignFileV1 is a cipher suite for signing files (no encryption).
	// SHA2_256 is chosen for better compatibility with other tool sets and workflows.
	SuiteSignFileV1 = registerSuite(&Suite{
		ID:            "signfile_v1",
		Tools:         []string{"Ed25519(SHA2-256)"},
		Provides:      newEmptyRequirements().Add(Integrity).Add(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusRecommended,
	})
	// SuiteCompleteV1 is a cipher suite for both encrypting for someone and signing.
	SuiteCompleteV1 = registerSuite(&Suite{
		ID:            "v1",
		Tools:         []string{"ECDH-X25519", "Ed25519(BLAKE2b-256)", "HKDF(BLAKE2b-256)", "CHACHA20-POLY1305"},
		Provides:      NewRequirements(),
		SecurityLevel: 128,
		Status:        SuiteStatusRecommended,
	})
	// SuiteWireV1 is a cipher suite for network communication, including authentication of the server, but not the client.
	SuiteWireV1 = registerSuite(&Suite{
		ID:            "w1",
		Tools:         []string{"ECDH-X25519", "HKDF(BLAKE2b-256)", "CHACHA20-POLY1305"},
		Provides:      NewRequirements().Remove(SenderAuthentication),
		SecurityLevel: 128,
		Status:        SuiteStatusRecommended,
	})

	// Currently Recommended Suites.

	// SuiteKey is a cipher suite for encryption with a key.
	SuiteKey = SuiteKeyV1
	// SuitePassword is a cipher suite for encryption with a password.
	SuitePassword = SuitePasswordV1
	// SuiteRcptOnly is a cipher suite for encrypting for someone, but without verifying the sender/source.
	SuiteRcptOnly = SuiteRcptOnlyV1
	// SuiteSign is a cipher suite for signing (no encryption).
	SuiteSign = SuiteSignV1
	// SuiteSignFile is a cipher suite for signing files (no encryption).
	SuiteSignFile = SuiteSignFileV1
	// SuiteComplete is a cipher suite for both encrypting for someone and signing.
	SuiteComplete = SuiteCompleteV1
	// SuiteWire is a cipher suite for network communication, including authentication of the server, but not the client.
	SuiteWire = SuiteWireV1
)

func registerSuite(suite *Suite) (suiteID string) {
	// add if not exists
	_, ok := suitesMap[suite.ID]
	if !ok {
		suitesMap[suite.ID] = suite
		suitesList = append(suitesList, suite)
	}

	return suite.ID
}

// GetSuite returns the suite with the given ID.
func GetSuite(suiteID string) (suite *Suite, ok bool) {
	suite, ok = suitesMap[suiteID]
	return
}

// Suites returns all registered suites as a slice.
func Suites() []*Suite {
	return suitesList
}

// SuitesMap returns all registered suites as a map.
func SuitesMap() map[string]*Suite {
	return suitesMap
}
