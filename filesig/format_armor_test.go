package jess

import (
	"bytes"
	"testing"

	"github.com/safing/jess"
	"github.com/safing/jess/lhash"
)

var (
	testFileSigOneKey = "7KoUBdrRfF6drrPvKianoGfEXTQFCS5wDbfQyc87VQnYApPckRS8SfrrmAXZhV1JgKfnh44ib9nydQVEDRJiZArV22RqMfPrJmQdoAsE7zuzPRSrku8yF7zfnEv46X5GsmgfdSDrFMdG7XJd3fdaxStYCXTYDS5R"

	testFileSigOneData = []byte("The quick brown fox jumps over the lazy dog")

	testFileSigOneMetaData = map[string]string{
		"id":      "resource/path",
		"version": "0.0.1",
	}

	testFileSigOneSignature = []byte(`
-----BEGIN JESS SIGNATURE-----
Q6VnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRA40a/BkRGF0YVhqTYOr
TGFiZWxlZEhhc2jEIhkgAXGM7DXNPXlt0AAg4L/stHOtI0V9Bjt17/KcD/ouWKmo
U2lnbmVkQXTW/2LH/ueoTWV0YURhdGGComlkrXJlc291cmNlL3BhdGindmVyc2lv
bqUwLjAuMWpTaWduYXR1cmVzgaNmU2NoZW1lZ0VkMjU1MTliSURwZmlsZXNpZy10
ZXN0LWtleWVWYWx1ZVhA4b1kfIJF7do6OcJnemQ5mtj/ZyMFJWWTmD1W5KvkpZac
2AP5f+dDJhzWBHsoSXTCl6uA3DA3+RbABMYAZn6eDg
-----END JESS SIGNATURE-----
`)
)

func TestFileSigFormat(t *testing.T) {
	t.Parallel()

	// Load test key.
	signet, err := jess.SignetFromBase58(testFileSigOneKey)
	if err != nil {
		t.Fatal(err)
	}

	// Store signet.
	if err := testTrustStore.StoreSignet(signet); err != nil {
		t.Fatal(err)
	}
	// Store public key for verification.
	recipient, err := signet.AsRecipient()
	if err != nil {
		t.Fatal(err)
	}
	if err := testTrustStore.StoreSignet(recipient); err != nil {
		t.Fatal(err)
	}

	// Create envelope.
	envelope := jess.NewUnconfiguredEnvelope()
	envelope.SuiteID = jess.SuiteSignV1
	envelope.Senders = []*jess.Signet{signet}

	// Hash and sign file.
	hash := lhash.Digest(lhash.BLAKE2b_256, testFileSigOneData)
	letter, _, err := SignFileData(hash, testFileSigOneMetaData, envelope, testTrustStore)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize signature.
	sigFile, err := MakeSigFileSection(letter)
	if err != nil {
		t.Fatal(err)
	}
	// fmt.Println("Signature:")
	// fmt.Println(string(sigFile))

	// Parse signature again.
	sigs, err := ParseSigFile(sigFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("one sig expected, got %d", len(sigs))
	}

	// Verify Signature.
	fileData, err := VerifyFileData(sigs[0], testFileSigOneMetaData, testTrustStore)
	if err != nil {
		t.Fatal(err)
	}

	// Verify File.
	if !fileData.FileHash().MatchesData(testFileSigOneData) {
		t.Fatal("file hash does not match")
	}

	// Verify the saved version of the signature.

	// Parse the saved signature.
	sigs, err = ParseSigFile(testFileSigOneSignature)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("only one sig expected, got %d", len(sigs))
	}

	// Verify Signature.
	fileData, err = VerifyFileData(sigs[0], testFileSigOneMetaData, testTrustStore)
	if err != nil {
		t.Fatal(err)
	}

	// Verify File.
	if !fileData.FileHash().MatchesData(testFileSigOneData) {
		t.Fatal("file hash does not match")
	}
}

var (
	testFileSigFormat1 = []byte(`TGFiZWxlZEhhc2jEIhkgAXGM7DXNPXlt0AAg4L
-----BEGIN JESS SIGNATURE-----
Q6VnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRA40a/BkRGF0YVhqTYOr
TGFiZWxlZEhhc2jEIhkgAXGM7DXNPXlt0AAg4L/stHOtI0V9Bjt17/KcD/ouWKmo
U2lnbmVkQXTW/2LH/ueoTWV0YURhdGGComlkrXJlc291cmNlL3BhdGindmVyc2lv
bqUwLjAuMWpTaWduYXR1cmVzgaNmU2NoZW1lZ0VkMjU1MTliSURwZmlsZXNpZy10
ZXN0LWtleWVWYWx1ZVhA4b1kfIJF7do6OcJnemQ5mtj/ZyMFJWWTmD1W5KvkpZac
2AP5f+dDJhzWBHsoSXTCl6uA3DA3+RbABMYAZn6eDg
-----END JESS SIGNATURE-----

-----END JESS SIGNATURE-----
-----BEGIN JESS SIGNATURE-----
Q6VnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRA40a/BkRGF0YVhqTYOr
	TGFiZWxlZEhhc2jEIhkgAXGM7DXNPXlt0AAg4L/stHOtI0V9Bjt17/KcD/ouWKmo
	U2lnbmVkQXTW/2LH/ueoTWV0YURhdGGComlk
rXJlc291cmNlL3BhdGindmVyc2lvbqUwLjAuMWpTaWduYXR1cmVzgaNmU2NoZW1lZ0VkMjU1MTliSURwZmlsZXNpZy10
	ZXN0LWtleWVWYWx1ZVhA4b1kfIJF7do6OcJnemQ5mtj/ZyMFJWWTmD1W5KvkpZac
2AP5f+dDJhzWBHsoSXTCl6uA3DA3+RbABMYAZn6eDg
-----END JESS SIGNATURE-----
end`)

	testFileSigFormat2 = []byte(`test data 1
-----BEGIN JESS SIGNATURE-----
invalid sig
-----END JESS SIGNATURE-----
test data 2`)

	testFileSigFormat3 = []byte(`test data 1
-----BEGIN JESS SIGNATURE-----
invalid sig
-----END JESS SIGNATURE-----
test data 2
-----BEGIN JESS SIGNATURE-----
Q6VnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRA40a/BkRGF0YVhqTYOr
TGFiZWxlZEhhc2jEIhkgAXGM7DXNPXlt0AAg4L/stHOtI0V9Bjt17/KcD/ouWKmo
U2lnbmVkQXTW/2LH/ueoTWV0YURhdGGComlkrXJlc291cmNlL3BhdGindmVyc2lv
bqUwLjAuMWpTaWduYXR1cmVzgaNmU2NoZW1lZ0VkMjU1MTliSURwZmlsZXNpZy10
ZXN0LWtleWVWYWx1ZVhA4b1kfIJF7do6OcJnemQ5mtj/ZyMFJWWTmD1W5KvkpZac
2AP5f+dDJhzWBHsoSXTCl6uA3DA3+RbABMYAZn6eDg
-----END JESS SIGNATURE-----`)

	testFileSigFormat4 = []byte(`test data 1
test data 2
-----BEGIN JESS SIGNATURE-----
Q6VnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRA40a/BkRGF0YVhqTYOr
TGFiZWxlZEhhc2jEIhkgAXGM7DXNPXlt0AAg4L/stHOtI0V9Bjt17/KcD/ouWKmo
U2lnbmVkQXTW/2LH/ueoTWV0YURhdGGComlkrXJlc291cmNlL3BhdGindmVyc2lv
bqUwLjAuMWpTaWduYXR1cmVzgaNmU2NoZW1lZ0VkMjU1MTliSURwZmlsZXNpZy10
ZXN0LWtleWVWYWx1ZVhA4b1kfIJF7do6OcJnemQ5mtj/ZyMFJWWTmD1W5KvkpZac
2AP5f+dDJhzWBHsoSXTCl6uA3DA3+RbABMYAZn6eDg
-----END JESS SIGNATURE-----`)
)

func TestFileSigFormatParsing(t *testing.T) {
	t.Parallel()

	sigs, err := ParseSigFile(testFileSigFormat1)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected two signatures, got %d", 1)
	}

	newFile, err := AddToSigFile(sigs[0], testFileSigFormat2, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newFile, testFileSigFormat3) {
		t.Fatalf("unexpected output:\n%s", string(newFile))
	}
	newFile, err = AddToSigFile(sigs[0], testFileSigFormat2, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newFile, testFileSigFormat4) {
		t.Fatalf("unexpected output:\n%s", string(newFile))
	}
}
