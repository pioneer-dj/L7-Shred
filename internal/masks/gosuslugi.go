package masks

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type GosuslugiMask struct {
	userID    uint64
	sessionID uint64
	requestID uint32
	timestamp uint32
}

func NewGosuslugiMask() *GosuslugiMask {
	m := &GosuslugiMask{
		userID:    0,
		sessionID: 0,
		requestID: 0,
		timestamp: uint32(time.Now().Unix()),
	}
	rand.Read([]byte{byte(m.userID)})
	rand.Read([]byte{byte(m.sessionID)})
	return m
}

func (g *GosuslugiMask) Wrap(payload []byte) []byte {
	g.requestID++
	g.timestamp = uint32(time.Now().Unix())

	header := make([]byte, 32)
	copy(header[0:12], []byte("GOSUSLUGI2"))
	binary.BigEndian.PutUint64(header[12:20], g.userID)
	binary.BigEndian.PutUint64(header[20:28], g.sessionID)
	binary.BigEndian.PutUint32(header[28:32], g.requestID)

	return append(header, payload...)
}

func (g *GosuslugiMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, ErrInvalidPacket
	}
	return data[32:], nil
}

func (g *GosuslugiMask) ID() string { return "gosuslugi" }
