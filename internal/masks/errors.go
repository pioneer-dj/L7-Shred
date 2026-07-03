package masks

import "errors"

var (
	ErrInvalidPacket = errors.New("invalid packet format")
	ErrUnwrapFailed  = errors.New("failed to unwrap packet")
	ErrCorruptedData = errors.New("data corruption detected")
)
