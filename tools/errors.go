package tools

import "errors"

var (
	// ErrNotFound is returned when a tool cannot be found.
	ErrNotFound = errors.New("does not exist")

	// ErrInvalidKey is returned when a invalid public or private key was supplied.
	ErrInvalidKey = errors.New("invalid key")

	// ErrNotImplemented is returned by the dummy functions if they are not overridden correctly.
	ErrNotImplemented = errors.New("not implemented")

	// ErrProtected is returned if an operation is executed, but the key is still protected.
	ErrProtected = errors.New("key is protected")
)
