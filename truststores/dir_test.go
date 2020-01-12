package truststores

func init() {
	// interface compliance test
	var testDirTrustStore ExtendedTrustStore
	testDirTrustStore, _ = NewDirTrustStore("/tmp")
	_ = testDirTrustStore
}
