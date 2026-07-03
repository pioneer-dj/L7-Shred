package masks

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type SberIDMask struct {
	clientID  uint64
	sessionID uint64
	requestID uint32
	timestamp uint32
}

func NewSberIDMask() *SberIDMask {
	m := &SberIDMask{
		clientID:  0,
		sessionID: 0,
		requestID: 0,
		timestamp: uint32(time.Now().Unix()),
	}
	rand.Read([]byte{byte(m.clientID)})
	rand.Read([]byte{byte(m.sessionID)})
	return m
}

func (s *SberIDMask) Wrap(payload []byte) []byte {
	s.requestID++
	s.timestamp = uint32(time.Now().Unix())

	header := make([]byte, 32)
	copy(header[0:12], []byte("SBERID/2.0"))
	binary.BigEndian.PutUint64(header[12:20], s.clientID)
	binary.BigEndian.PutUint64(header[20:28], s.sessionID)
	binary.BigEndian.PutUint32(header[28:32], s.requestID)

	return append(header, payload...)
}

func (s *SberIDMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, ErrInvalidPacket
	}
	return data[32:], nil
}

func (s *SberIDMask) ID() string { return "sberid" }
