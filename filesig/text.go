package filesig

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/safing/jess/lhash"
)

// Text file metadata keys.
const (
	TextKeyPrefix    = "jess-"
	TextChecksumKey  = TextKeyPrefix + "checksum"
	TextSignatureKey = TextKeyPrefix + "signature"
)

// Text Operation Errors.
var (
	ErrChecksumMissing  = errors.New("no checksum found")
	ErrChecksumFailed   = errors.New("checksum does not match")
	ErrSignatureMissing = errors.New("signature not found")
	ErrSignatureFailed  = errors.New("signature does not match")
)

// TextPlacement signifies where jess metadata is put in text files.
type TextPlacement string

const (
	// TextPlacementTop places the metadata at end of file.
	TextPlacementTop TextPlacement = "top"
	// TextPlacementBottom places the metadata at end of file.
	TextPlacementBottom TextPlacement = "bottom"
	// TextPlacementAfterComment places the metadata at end of the top comment
	// block, or at the top, if the first line is not a comment.
	TextPlacementAfterComment TextPlacement = "after-comment"

	defaultMetaPlacement = TextPlacementAfterComment
)

// AddTextFileChecksum adds a checksum to a text file.
func AddTextFileChecksum(data []byte, commentSign string, placement TextPlacement) ([]byte, error) {
	// Split text file into content and jess metadata lines.
	content, metaLines, err := textSplit(data, commentSign)
	if err != nil {
		return nil, err
	}

	// Calculate checksum.
	h := lhash.BLAKE2b_256.Digest(content)
	metaLines = append(metaLines, TextChecksumKey+": "+h.Base58())

	// Sort and deduplicate meta lines.
	slices.Sort[[]string, string](metaLines)
	metaLines = slices.Compact[[]string, string](metaLines)

	// Add meta lines and return.
	return textAddMeta(content, metaLines, commentSign, placement)
}

// VerifyTextFileChecksum checks a checksum in a text file.
func VerifyTextFileChecksum(data []byte, commentSign string) error {
	// Split text file into content and jess metadata lines.
	content, metaLines, err := textSplit(data, commentSign)
	if err != nil {
		return err
	}

	// Verify all checksums.
	var checksumsVerified int
	for _, line := range metaLines {
		if strings.HasPrefix(line, TextChecksumKey) {
			// Clean key, delimiters and space.
			line = strings.TrimPrefix(line, TextChecksumKey)
			line = strings.TrimSpace(line)   // Spaces and newlines.
			line = strings.Trim(line, ":= ") // Delimiters and spaces.
			// Parse checksum.
			h, err := lhash.FromBase58(line)
			if err != nil {
				return fmt.Errorf("%w: failed to parse labeled hash: %w", ErrChecksumFailed, err)
			}
			// Verify checksum.
			if !h.Matches(content) {
				return ErrChecksumFailed
			}
			checksumsVerified++
		}
	}

	// Fail when no checksums were verified.
	if checksumsVerified == 0 {
		return ErrChecksumMissing
	}

	return nil
}

func textSplit(data []byte, commentSign string) (content []byte, metaLines []string, err error) {
	metaLinePrefix := commentSign + " " + TextKeyPrefix
	contentBuf := bytes.NewBuffer(make([]byte, 0, len(data)))
	metaLines = make([]string, 0, 1)

	// Find jess metadata lines.
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Split(scanRawLines)
	for s.Scan() {
		if strings.HasPrefix(s.Text(), metaLinePrefix) {
			metaLines = append(metaLines, strings.TrimSpace(strings.TrimPrefix(s.Text(), commentSign)))
		} else {
			_, _ = contentBuf.Write(s.Bytes())
		}
	}
	if s.Err() != nil {
		return nil, nil, s.Err()
	}

	return bytes.TrimSpace(contentBuf.Bytes()), metaLines, nil
}

func detectLineEndFormat(data []byte) (lineEnd string) {
	i := bytes.IndexByte(data, '\n')
	switch i {
	case -1:
		// Default to just newline.
		return "\n"
	case 0:
		// File start with a newline.
		return "\n"
	default:
		// First newline is at second byte or later.
		if bytes.Equal(data[i-1:i+1], []byte("\r\n")) {
			return "\r\n"
		}
		return "\n"
	}
}

func textAddMeta(data []byte, metaLines []string, commentSign string, position TextPlacement) ([]byte, error) {
	// Prepare new buffer.
	requiredSize := len(data)
	for _, line := range metaLines {
		requiredSize += len(line) + len(commentSign) + 3 // space + CRLF
	}
	contentBuf := bytes.NewBuffer(make([]byte, 0, requiredSize))

	// Find line ending.
	lineEnd := detectLineEndFormat(data)

	// Find jess metadata lines.
	if position == "" {
		position = defaultMetaPlacement
	}

	switch position {
	case TextPlacementTop:
		textWriteMetaLines(metaLines, commentSign, lineEnd, contentBuf)
		contentBuf.Write(data)
		// Add final newline.
		contentBuf.WriteString(lineEnd)

	case TextPlacementBottom:
		contentBuf.Write(data)
		// Add to newlines when appending, as content is first whitespace-stripped.
		contentBuf.WriteString(lineEnd)
		contentBuf.WriteString(lineEnd)
		textWriteMetaLines(metaLines, commentSign, lineEnd, contentBuf)

	case TextPlacementAfterComment:
		metaWritten := false
		s := bufio.NewScanner(bytes.NewReader(data))
		s.Split(scanRawLines)
		for s.Scan() {
			switch {
			case metaWritten:
				_, _ = contentBuf.Write(s.Bytes())
			case strings.HasPrefix(s.Text(), commentSign):
				_, _ = contentBuf.Write(s.Bytes())
			default:
				textWriteMetaLines(metaLines, commentSign, lineEnd, contentBuf)
				metaWritten = true
				_, _ = contentBuf.Write(s.Bytes())
			}
		}
		if s.Err() != nil {
			return nil, s.Err()
		}
		// If we have scanned through the file, and meta was not written, write it now.
		if !metaWritten {
			textWriteMetaLines(metaLines, commentSign, lineEnd, contentBuf)
		}
		// Add final newline.
		contentBuf.WriteString(lineEnd)
	}

	return contentBuf.Bytes(), nil
}

func textWriteMetaLines(metaLines []string, commentSign string, lineEnd string, writer io.StringWriter) {
	for _, line := range metaLines {
		_, _ = writer.WriteString(commentSign)
		_, _ = writer.WriteString(" ")
		_, _ = writer.WriteString(line)
		_, _ = writer.WriteString(lineEnd)
	}
}

// scanRawLines is a split function for a Scanner that returns each line of
// text, including any trailing end-of-line marker. The returned line may
// be empty. The end-of-line marker is one optional carriage return followed
// by one mandatory newline. In regular expression notation, it is `\r?\n`.
// The last non-empty line of input will be returned even if it has no
// newline.
func scanRawLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, data[0 : i+1], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
