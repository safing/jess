package filesig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTextChecksums(t *testing.T) {
	t.Parallel()

	// Base test text file.
	text := `#!/bin/bash
# Initial
# Comment
# Block

do_something()`

	// Test with checksum after comment.

	textWithChecksumAfterComment := `#!/bin/bash
# Initial
# Comment
# Block
# jess-checksum: ZwngYUfUBeUn99HSdrNxkWSNjqrgZuSpVrexeEYttBso5o

do_something()
`

	testTextWithChecksumAfterComment, err := AddTextFileChecksum([]byte(text), "#", TextPlacementAfterComment)
	require.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, textWithChecksumAfterComment, string(testTextWithChecksumAfterComment), "should match")
	require.NoError(t,
		VerifyTextFileChecksum(testTextWithChecksumAfterComment, "#"),
		"checksum should be correct",
	)
	require.NoError(t,
		VerifyTextFileChecksum(append(
			[]byte("\n\n  \r\n"),
			testTextWithChecksumAfterComment...,
		), "#"),
		"checksum should be correct",
	)
	require.NoError(t,
		VerifyTextFileChecksum(append(
			testTextWithChecksumAfterComment,
			[]byte("\r\n \n \n")...,
		), "#"),
		"checksum should be correct",
	)

	// Test with checksum at top.

	textWithChecksumAtTop := `# jess-checksum: ZwngYUfUBeUn99HSdrNxkWSNjqrgZuSpVrexeEYttBso5o
#!/bin/bash
# Initial
# Comment
# Block

do_something()
`

	testTextWithChecksumAtTop, err := AddTextFileChecksum([]byte(text), "#", TextPlacementTop)
	require.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, textWithChecksumAtTop, string(testTextWithChecksumAtTop), "should match")
	require.NoError(t,
		VerifyTextFileChecksum(testTextWithChecksumAtTop, "#"),
		"checksum should be correct",
	)

	// Test with checksum at bottom.

	textWithChecksumAtBottom := `#!/bin/bash
# Initial
# Comment
# Block

do_something()

# jess-checksum: ZwngYUfUBeUn99HSdrNxkWSNjqrgZuSpVrexeEYttBso5o
`

	testTextWithChecksumAtBottom, err := AddTextFileChecksum([]byte(text), "#", TextPlacementBottom)
	require.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, textWithChecksumAtBottom, string(testTextWithChecksumAtBottom), "should match")
	require.NoError(t,
		VerifyTextFileChecksum(testTextWithChecksumAtBottom, "#"),
		"checksum should be correct",
	)

	// Test with multiple checksums.

	textWithMultiChecksum := `# jess-checksum: PTNktssvYCYjZXLFL2QoBk7DYoSz1qF7DJd5XNvtptd41B
#!/bin/bash
# Initial
# Comment
# Block
# jess-checksum: Cy2TyVDjEStUqX3wCzCCKTfy228KaQK25ZDbHNmKiF8SPf

do_something()

# jess-checksum: YdgJFzuvFduk1MwRjZ2JkWQ6tCE1wkjn9xubSggKAdJSX5
`
	assert.NoError(t,
		VerifyTextFileChecksum([]byte(textWithMultiChecksum), "#"),
		"checksum should be correct",
	)

	textWithMultiChecksumOutput := `#!/bin/bash
# Initial
# Comment
# Block
# jess-checksum: Cy2TyVDjEStUqX3wCzCCKTfy228KaQK25ZDbHNmKiF8SPf
# jess-checksum: PTNktssvYCYjZXLFL2QoBk7DYoSz1qF7DJd5XNvtptd41B
# jess-checksum: YdgJFzuvFduk1MwRjZ2JkWQ6tCE1wkjn9xubSggKAdJSX5
# jess-checksum: ZwngYUfUBeUn99HSdrNxkWSNjqrgZuSpVrexeEYttBso5o

do_something()
`
	testTextWithMultiChecksumOutput, err := AddTextFileChecksum([]byte(textWithMultiChecksum), "#", TextPlacementAfterComment)
	require.NoError(t, err, "should be able to add checksum")
	assert.Equal(t, textWithMultiChecksumOutput, string(testTextWithMultiChecksumOutput), "should match")

	// Test failing checksums.

	textWithFailingChecksums := `#!/bin/bash
# Initial
# Comment
# Block
# jess-checksum: Cy2TyVDjEStUqX3wCzCCKTfy228KaQK25ZDbHNmKiF8SPf
# jess-checksum: PTNktssvYCYjZXLFL2QoBk7DYoSz1qF7DJd5XNvtptd41B
# jess-checksum: YdgJFzuvFduk1MwRjZ2JkWQ6tCE1wkjn9xubSggKAdJSX5
# jess-checksum: ZwngYUfUBeUn99HSdrNxkWSNjaaaaaaaaaaaaaaaaaaaaa

do_something()
`
	require.Error(t, VerifyTextFileChecksum([]byte(textWithFailingChecksums), "#"), "should fail")
}

func TestLineEndDetection(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"\n",
		detectLineEndFormat(nil),
		"empty data should default to simple lf ending",
	)
	assert.Equal(t,
		"\n",
		detectLineEndFormat([]byte("\n")),
		"shoud detect lf ending with empty first line",
	)
	assert.Equal(t,
		"\r\n",
		detectLineEndFormat([]byte("\r\n")),
		"shoud detect crlf ending with empty first line",
	)
	assert.Equal(t,
		"\n",
		detectLineEndFormat([]byte("abc\n")),
		"shoud detect lf ending with data on single line",
	)
	assert.Equal(t,
		"\r\n",
		detectLineEndFormat([]byte("abc\r\n")),
		"shoud detect crlf ending with data on single line",
	)
	assert.Equal(t,
		"\n",
		detectLineEndFormat([]byte("abc\nabc\r\n")),
		"shoud detect lf ending with data on first line",
	)
	assert.Equal(t,
		"\r\n",
		detectLineEndFormat([]byte("abc\r\nabc\n")),
		"shoud detect crlf ending with data on first line",
	)
}
