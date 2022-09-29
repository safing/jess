package jess

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Keywords and Prefixes for the export text format.
const (
	ExportSenderKeyword = "sender"
	ExportSenderPrefix  = "sender:"

	ExportRecipientKeyword = "recipient"
	ExportRecipientPrefix  = "recipient:"

	ExportKeyKeyword = "secret"
	ExportKeyPrefix  = "secret:"

	ExportEnvelopeKeyword = "envelope"
	ExportEnvelopePrefix  = "envelope:"
)

// Export exports the public part of a signet in text format.
func (signet *Signet) Export(short bool) (textFormat string, err error) {
	// Make public if needed.
	if !signet.Public {
		signet, err = signet.AsRecipient()
		if err != nil {
			return "", err
		}
	}

	// Transform to text format.
	return signet.toTextFormat(short)
}

// Backup exports the private part of a signet in text format.
func (signet *Signet) Backup(short bool) (textFormat string, err error) {
	// Abprt if public.
	if signet.Public {
		return "", errors.New("cannot backup (only export) a recipient")
	}

	// Transform to text format.
	return signet.toTextFormat(short)
}

func (signet *Signet) toTextFormat(short bool) (textFormat string, err error) {
	// Serialize to base58.
	base58data, err := signet.ToBase58()
	if err != nil {
		return "", err
	}

	// Define keywords.
	var keyword, typeComment string
	switch {
	case signet.Scheme == SignetSchemePassword:
		return "", errors.New("cannot backup or export passwords")
	case signet.Scheme == SignetSchemeKey:
		// Check if the signet is marked as "public".
		if signet.Public {
			return "", errors.New("cannot export keys")
		}
		keyword = ExportKeyKeyword
		typeComment = "symmetric-key"
	case signet.Public:
		keyword = ExportRecipientKeyword
		typeComment = fmt.Sprintf(
			"public-%s-key", toTextFormatString(signet.Scheme),
		)
	default:
		keyword = ExportSenderKeyword
		typeComment = fmt.Sprintf(
			"private-%s-key", toTextFormatString(signet.Scheme),
		)
	}

	// Transform to text format.
	if short {
		return fmt.Sprintf(
			"%s:%s",
			keyword,
			base58data,
		), nil
	}
	return fmt.Sprintf(
		"%s:%s:%s:%s",
		keyword,
		typeComment,
		toTextFormatString(signet.Info.Name),
		base58data,
	), nil
}

// Export exports the envelope in text format.
func (e *Envelope) Export(short bool) (textFormat string, err error) {
	// Remove and key data.
	e.CleanSignets()

	// Serialize to base58.
	base58data, err := e.ToBase58()
	if err != nil {
		return "", err
	}

	// Transform to text format.
	if short {
		return fmt.Sprintf(
			"%s:%s",
			ExportEnvelopeKeyword,
			base58data,
		), nil
	}
	return fmt.Sprintf(
		"%s:%s:%s:%s",
		ExportEnvelopeKeyword,
		e.SuiteID,
		e.Name,
		base58data,
	), nil
}

// KeyFromTextFormat loads a secret key from the text format.
func KeyFromTextFormat(textFormat string) (*Signet, error) {
	// Check the identifier.
	if !strings.HasPrefix(textFormat, ExportKeyPrefix) {
		return nil, errors.New("not a secret")
	}

	// Parse the data section.
	splitted := strings.Split(textFormat, ":")
	if len(splitted) < 2 {
		return nil, errors.New("invalid format")
	}
	return SignetFromBase58(splitted[len(splitted)-1])
}

// SenderFromTextFormat loads a sender (private key) from the text format.
func SenderFromTextFormat(textFormat string) (*Signet, error) {
	// Check the identifier.
	if !strings.HasPrefix(textFormat, ExportSenderPrefix) {
		return nil, errors.New("not a sender")
	}

	// Parse the data section.
	splitted := strings.Split(textFormat, ":")
	if len(splitted) < 2 {
		return nil, errors.New("invalid format")
	}
	return SignetFromBase58(splitted[len(splitted)-1])
}

// RecipientFromTextFormat loads a recipient (public key) from the text format.
func RecipientFromTextFormat(textFormat string) (*Signet, error) {
	// Check the identifier.
	if !strings.HasPrefix(textFormat, ExportRecipientPrefix) {
		return nil, errors.New("not a recipient")
	}

	// Parse the data section.
	splitted := strings.Split(textFormat, ":")
	if len(splitted) < 2 {
		return nil, errors.New("invalid format")
	}
	return SignetFromBase58(splitted[len(splitted)-1])
}

// EnvelopeFromTextFormat loads an envelope from the text format.
func EnvelopeFromTextFormat(textFormat string) (*Envelope, error) {
	// Check the identifier.
	if !strings.HasPrefix(textFormat, ExportEnvelopePrefix) {
		return nil, errors.New("not an envelope")
	}

	// Parse the data section.
	splitted := strings.Split(textFormat, ":")
	if len(splitted) < 2 {
		return nil, errors.New("invalid format")
	}
	return EnvelopeFromBase58(splitted[len(splitted)-1])
}

var replaceForTextFormatMatcher = regexp.MustCompile(`[^A-Za-z0-9]+`)

// toTextFormatString makes a string compatible with the text format.
func toTextFormatString(s string) string {
	return strings.ToLower(
		strings.Trim(
			replaceForTextFormatMatcher.ReplaceAllString(s, "-"), "-",
		),
	)
}
