package filesig

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, jsonWithChecksum, string(testJSONWithChecksum), "should match")
	assert.NoError(t,
		VerifyJSONChecksum(testJSONWithChecksum),
		"checksum should be correct",
	)

	jsonWithChecksum = `{
	"c": 1,     "a":"b",
		"_jess-checksum": "ZwtAd75qvioh6uf1NAq64KRgTbqeehFVYmhLmrwu1s7xJo"
	}`
	assert.NoError(t,
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
	assert.NoError(t,
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
	assert.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, jsonWithMultiChecksumOutput, string(testJSONWithMultiChecksum), "should match")
	assert.NoError(t,
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
