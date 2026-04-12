package transport

import "errors"

var (
	ErrMissingAddress   = errors.New("missing listen or server address")
	ErrInvalidMTU       = errors.New("MTU must be between 576 and 9000")
	ErrConnectionClosed = errors.New("connection closed")
)
