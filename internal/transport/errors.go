package transport

import "errors"

var (
	ErrMissingAddress     = errors.New("missing listen or server address")
	ErrInvalidMTU         = errors.New("MTU must be between 576 and 9000")
	ErrInvalidFragmentMin = errors.New("fragment min must be between 32 and 1500")
	ErrInvalidFragmentMax = errors.New("fragment max must be between fragment min and 1500")
	ErrConnectionClosed   = errors.New("connection closed")
	ErrInvalidConfig      = errors.New("invalid configuration")
	ErrHandshakeFailed    = errors.New("handshake failed")
	ErrSessionNotFound    = errors.New("session not found")
)
