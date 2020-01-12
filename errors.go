package jess

import "errors"

var (
	// ErrIntegrityViolation is returned when the integrity was found the be violated.
	ErrIntegrityViolation = errors.New("integrity violation")
	// ErrConfidentialityViolation is returned when the confidentiality was found the be violated.
	ErrConfidentialityViolation = errors.New("confidentiality violation")
	// ErrAuthenticityViolation is returned when the authenticity was found the be violated.
	ErrAuthenticityViolation = errors.New("authenticity violation")

	// ErrInsufficientRandom is returned if the configured RNG cannot deliver enough data.
	ErrInsufficientRandom = errors.New("not enough random data available from source")
)
