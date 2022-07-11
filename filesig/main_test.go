package filesig

import (
	"errors"
	"testing"
	"time"

	"github.com/safing/jess"
	"github.com/safing/jess/lhash"
	"github.com/safing/jess/tools"
)

var (
	testTrustStore = jess.NewMemTrustStore()
	testData1      = "The quick brown fox jumps over the lazy dog. "

	testFileSigMetaData1 = map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	testFileSigMetaData1x = map[string]string{
		"key1": "value1x",
	}
	testFileSigMetaData2 = map[string]string{
		"key3": "value3",
		"key4": "value4",
	}
	testFileSigMetaData3 = map[string]string{}
)

func TestFileSigs(t *testing.T) {
	t.Parallel()

	testFileSigningWithOptions(t, testFileSigMetaData1, testFileSigMetaData1, true)
	testFileSigningWithOptions(t, testFileSigMetaData1, testFileSigMetaData1x, false)
	testFileSigningWithOptions(t, testFileSigMetaData2, testFileSigMetaData2, true)
	testFileSigningWithOptions(t, testFileSigMetaData1, testFileSigMetaData2, false)
	testFileSigningWithOptions(t, testFileSigMetaData2, testFileSigMetaData1, false)
	testFileSigningWithOptions(t, testFileSigMetaData1, testFileSigMetaData3, true)
	testFileSigningWithOptions(t, testFileSigMetaData3, testFileSigMetaData1, false)
}

func testFileSigningWithOptions(t *testing.T, signingMetaData, verifyingMetaData map[string]string, shouldSucceed bool) {
	t.Helper()

	// Get tool for key generation.
	tool, err := tools.Get("Ed25519")
	if err != nil {
		t.Fatal(err)
	}

	// Generate key pair.
	s, err := getOrMakeSignet(t, tool.StaticLogic, false, "test-key-filesig-1")
	if err != nil {
		t.Fatal(err)
	}

	// Hash "file".
	fileHash := lhash.BLAKE2b_256.Digest([]byte(testData1))

	// Make envelope.
	envelope := jess.NewUnconfiguredEnvelope()
	envelope.SuiteID = jess.SuiteSignV1
	envelope.Senders = []*jess.Signet{s}

	// Sign data.
	letter, fileData, err := SignFileData(fileHash, signingMetaData, envelope, testTrustStore)
	if err != nil {
		t.Fatal(err)
	}

	// Check if the checksum made it.
	if len(fileData.LabeledHash) == 0 {
		t.Fatal("missing labeled hash")
	}

	// Verify signature.
	_, err = VerifyFileData(letter, verifyingMetaData, testTrustStore)
	if (err == nil) != shouldSucceed {
		t.Fatal(err)
	}
}

func getOrMakeSignet(t *testing.T, tool tools.ToolLogic, recipient bool, signetID string) (*jess.Signet, error) {
	t.Helper()

	// check if signet already exists
	signet, err := testTrustStore.GetSignet(signetID, recipient)
	if err == nil {
		return signet, nil
	}

	// handle special cases
	if tool == nil {
		return nil, errors.New("bad parameters")
	}

	// create new signet
	newSignet := jess.NewSignetBase(tool.Definition())
	newSignet.ID = signetID
	// generate signet and log time taken
	start := time.Now()
	err = tool.GenerateKey(newSignet)
	if err != nil {
		return nil, err
	}
	t.Logf("generated %s signet %s in %s", newSignet.Scheme, newSignet.ID, time.Since(start))

	// store signet
	err = testTrustStore.StoreSignet(newSignet)
	if err != nil {
		return nil, err
	}

	// store recipient
	newRcpt, err := newSignet.AsRecipient()
	if err != nil {
		return nil, err
	}
	err = testTrustStore.StoreSignet(newRcpt)
	if err != nil {
		return nil, err
	}

	// return
	if recipient {
		return newRcpt, nil
	}
	return newSignet, nil
}
