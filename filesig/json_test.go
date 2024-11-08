package filesig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safing/jess"
	"github.com/safing/jess/tools"
)

func TestJSONChecksums(t *testing.T) {
	t.Parallel()

	// Base test text file.
	json := `{"a": "b", "c": 1}`

	// Test with checksum after comment.

	jsonWithChecksum := `{
 "_jess-checksum": "ZwtAd75qvioh6uf1NAq64KRgTbqeehFVYmhLmrwu1s7xJo",
 "a": "b",
 "c": 1
}
`

	testJSONWithChecksum, err := AddJSONChecksum([]byte(json))
	require.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, jsonWithChecksum, string(testJSONWithChecksum), "should match")
	require.NoError(t,
		VerifyJSONChecksum(testJSONWithChecksum),
		"checksum should be correct",
	)

	jsonWithChecksum = `{
	"c": 1,     "a":"b",
		"_jess-checksum": "ZwtAd75qvioh6uf1NAq64KRgTbqeehFVYmhLmrwu1s7xJo"
	}`
	require.NoError(t,
		VerifyJSONChecksum([]byte(jsonWithChecksum)),
		"checksum should be correct",
	)

	jsonWithMultiChecksum := `{
		"_jess-checksum": [
			"PTV7S3Ca81aRk2kdNw7q2RfjLfEdPPT5Px5d211nhZedZC",
			"PTV7S3Ca81aRk2kdNw7q2RfjLfEdPPT5Px5d211nhZedZC",
			"CyDGH55DZUwa556DiYztMXaKZVBDjzWeFETiGmABMbvC3V"
		],
		"a": "b",
		"c": 1
	 }
	 `
	require.NoError(t,
		VerifyJSONChecksum([]byte(jsonWithMultiChecksum)),
		"checksum should be correct",
	)

	jsonWithMultiChecksumOutput := `{
 "_jess-checksum": ["CyDGH55DZUwa556DiYztMXaKZVBDjzWeFETiGmABMbvC3V", "PTV7S3Ca81aRk2kdNw7q2RfjLfEdPPT5Px5d211nhZedZC", "ZwtAd75qvioh6uf1NAq64KRgTbqeehFVYmhLmrwu1s7xJo"],
 "a": "b",
 "c": 1
}
`

	testJSONWithMultiChecksum, err := AddJSONChecksum([]byte(jsonWithMultiChecksum))
	require.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, jsonWithMultiChecksumOutput, string(testJSONWithMultiChecksum), "should match")
	require.NoError(t,
		VerifyJSONChecksum(testJSONWithMultiChecksum),
		"checksum should be correct",
	)

	// 	// Test with multiple checksums.

	// 	textWithMultiChecksum := `# jess-checksum: PTNktssvYCYjZXLFL2QoBk7DYoSz1qF7DJd5XNvtptd41B
	// #!/bin/bash
	// # Initial
	// # Comment
	// # Block
	// # jess-checksum: Cy2TyVDjEStUqX3wCzCCKTfy228KaQK25ZDbHNmKiF8SPf

	// do_something()

	// # jess-checksum: YdgJFzuvFduk1MwRjZ2JkWQ6tCE1wkjn9xubSggKAdJSX5
	// `
	// 	assert.NoError(t,
	// 		VerifyTextFileChecksum([]byte(textWithMultiChecksum), "#"),
	// 		"checksum should be correct",
	// 	)

	// 	textWithMultiChecksumOutput := `#!/bin/bash
	// # Initial
	// # Comment
	// # Block
	// # jess-checksum: Cy2TyVDjEStUqX3wCzCCKTfy228KaQK25ZDbHNmKiF8SPf
	// # jess-checksum: PTNktssvYCYjZXLFL2QoBk7DYoSz1qF7DJd5XNvtptd41B
	// # jess-checksum: YdgJFzuvFduk1MwRjZ2JkWQ6tCE1wkjn9xubSggKAdJSX5
	// # jess-checksum: ZwngYUfUBeUn99HSdrNxkWSNjqrgZuSpVrexeEYttBso5o

	// do_something()
	// `
	// 	testTextWithMultiChecksumOutput, err := AddTextFileChecksum([]byte(textWithMultiChecksum), "#", AfterComment)
	// 	assert.NoError(t, err, "should be able to add checksum")
	// 	assert.Equal(t, textWithMultiChecksumOutput, string(testTextWithMultiChecksumOutput), "should match")

	// 	// Test failing checksums.

	// 	textWithFailingChecksums := `#!/bin/bash
	// # Initial
	// # Comment
	// # Block
	// # jess-checksum: Cy2TyVDjEStUqX3wCzCCKTfy228KaQK25ZDbHNmKiF8SPf
	// # jess-checksum: PTNktssvYCYjZXLFL2QoBk7DYoSz1qF7DJd5XNvtptd41B
	// # jess-checksum: YdgJFzuvFduk1MwRjZ2JkWQ6tCE1wkjn9xubSggKAdJSX5
	// # jess-checksum: ZwngYUfUBeUn99HSdrNxkWSNjaaaaaaaaaaaaaaaaaaaaa

	// do_something()
	// `
	//
	//	assert.Error(t, VerifyTextFileChecksum([]byte(textWithFailingChecksums), "#"), "should fail")
}

func TestJSONSignatures(t *testing.T) {
	t.Parallel()

	// Get tool for key generation.
	tool, err := tools.Get("Ed25519")
	if err != nil {
		t.Fatal(err)
	}

	// Generate key pair.
	s, err := getOrMakeSignet(t, tool.StaticLogic, false, "test-key-jsonsig-1")
	if err != nil {
		t.Fatal(err)
	}
	// sBackup, err := s.Backup(true)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// t.Logf("signet: %s", sBackup)

	// Make envelope.
	envelope := jess.NewUnconfiguredEnvelope()
	envelope.SuiteID = jess.SuiteSignV1
	envelope.Senders = []*jess.Signet{s}

	// Test 1: Simple json.

	json := `{"a": "b", "c": 1}`
	testJSONWithSignature, err := AddJSONSignature([]byte(json), envelope, testTrustStore)
	require.NoError(t, err, "should be able to add signature")
	require.NoError(t,
		VerifyJSONSignature(testJSONWithSignature, testTrustStore),
		"signature should be valid",
	)

	// Test 2: Prepared json with signature.

	// Load signing key into trust store.
	signingKey2, err := jess.SenderFromTextFormat(
		"sender:2ZxXzzL3mc3mLPizTUe49zi8Z3NMbDrmmqJ4V9mL4AxefZ1o8pM8wPMuK2uW12Mvd3EJL9wsKTn14BDuqH2AtucvHTAkjDdZZ5YA9Azmji5tLRXmypvSxEj2mxXU3MFXBVdpzPdwRcE4WauLo9ZfQWebznvnatVLwuxmeo17tU2pL7",
	)
	if err != nil {
		t.Fatal(err)
	}
	rcptKey2, err := signingKey2.AsRecipient()
	if err != nil {
		t.Fatal(err)
	}
	if err := testTrustStore.StoreSignet(rcptKey2); err != nil {
		t.Fatal(err)
	}

	// Verify data.
	jsonWithSignature := `{
			"c":1,"a":"b",
			"_jess-signature": "Q6RnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRK6e7JhqU2lnbmF0dXJlc4GjZlNjaGVtZWdFZDI1NTE5YklEeBl0ZXN0LXN0YXRpYy1rZXktanNvbnNpZy0xZVZhbHVlWEBPEbeM4_CTl3OhNT2z74h38jIZG5R7BBLDFd6npJ3E-4JqM6TaSMa-2pPEBf3fDNuikR3ak45SekC6Z10uWiEB"
		}`
	require.NoError(t,
		VerifyJSONSignature([]byte(jsonWithSignature), testTrustStore),
		"signature should be valid",
	)

	// Test 3: Add signature to prepared json.

	testJSONWithSignature, err = AddJSONSignature([]byte(jsonWithSignature), envelope, testTrustStore)
	require.NoError(t, err, "should be able to add signature")
	require.NoError(t,
		VerifyJSONSignature(testJSONWithSignature, testTrustStore),
		"signatures should be valid",
	)

	// Test 4: Prepared json with multiple signatures.

	// Load signing key into trust store.
	signingKey3, err := jess.SenderFromTextFormat(
		"sender:2ZxXzzL3mc3mLPizTUe49zi8Z3NMbDrmmqJ4V9mL4AxefZ1o8pM8wPMuRAXdZNaPX3B96bhGCpww6TbXJ6WXLHoLwLV196cgdm1BurfTMdjUPa4PUj1KgHuM82b1p8ezQeryzj1CsjeM8KRQdh9YP87gwKpXNmLW5GmUyWG5KxzZ7W",
	)
	if err != nil {
		t.Fatal(err)
	}
	rcptKey3, err := signingKey3.AsRecipient()
	if err != nil {
		t.Fatal(err)
	}
	if err := testTrustStore.StoreSignet(rcptKey3); err != nil {
		t.Fatal(err)
	}

	jsonWithMultiSig := `{
			"_jess-signature": [
				"Q6RnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRK6e7JhqU2lnbmF0dXJlc4GjZlNjaGVtZWdFZDI1NTE5YklEeBl0ZXN0LXN0YXRpYy1rZXktanNvbnNpZy0xZVZhbHVlWEBPEbeM4_CTl3OhNT2z74h38jIZG5R7BBLDFd6npJ3E-4JqM6TaSMa-2pPEBf3fDNuikR3ak45SekC6Z10uWiEB",
				"Q6RnVmVyc2lvbgFnU3VpdGVJRGdzaWduX3YxZU5vbmNlRC32oylqU2lnbmF0dXJlc4GjZlNjaGVtZWdFZDI1NTE5YklEeBl0ZXN0LXN0YXRpYy1rZXktanNvbnNpZy0yZVZhbHVlWEDYVHeKaJvzZPOkgC6Tie6x70bNm2jtmJmAwDFDcBL1ddK7pVSefyAPg47xMO7jeucP5bw754P6CdrR5gyANJkM"
			],
			"a": "b",
			"c": 1
		 }
		 `
	assert.NoError(t,
		VerifyJSONSignature([]byte(jsonWithMultiSig), testTrustStore),
		"signatures should be valid",
	)
}
