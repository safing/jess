package jess

// Currently Recommended Suites.
var (
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

// Suite Lists.
var (
	suitesMap  = make(map[string]*Suite)
	suitesList []*Suite
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
